import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from transformers import (
    DistilBertTokenizer,
    DistilBertForSequenceClassification,
    get_linear_schedule_with_warmup
)
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
import os
import matplotlib.pyplot as plt
import seaborn as sns
from tqdm import tqdm
import warnings
import time
from datetime import datetime

warnings.filterwarnings('ignore')

# Fix device specification
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu') 
print(f"Using device: {device}")

class NetworkTrafficDataset(Dataset):
    """Dataset for network traffic classification"""
    def __init__(self, texts, labels, tokenizer, max_length=128):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])
        label = self.labels[idx]
        
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )
        
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }

class NetworkIDSClassifier:
    """Network IDS Classifier using DistilBERT"""
    def __init__(self):
        self.tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
        self.model = None
        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.class_names = []
        
    def numerical_to_text(self, row):
        """Convert numerical features to descriptive text"""
        text_parts = []
        
        # Flow characteristics
        if 'Flow Duration' in row:
            duration = row['Flow Duration']
            if duration < 1000:
                text_parts.append("short_duration")
            elif duration < 10000:
                text_parts.append("medium_duration")
            else:
                text_parts.append("long_duration")
        
        # Packet counts
        if 'Total Fwd Packet' in row:
            fwd_packets = row['Total Fwd Packet']
            if fwd_packets < 10:
                text_parts.append("few_forward_packets")
            elif fwd_packets < 100:
                text_parts.append("moderate_forward_packets")
            else:
                text_parts.append("many_forward_packets")
        
        if 'Total Bwd packets' in row:
            bwd_packets = row['Total Bwd packets']
            if bwd_packets < 10:
                text_parts.append("few_backward_packets")
            elif bwd_packets < 100:
                text_parts.append("moderate_backward_packets")
            else:
                text_parts.append("many_backward_packets")
        
        # Flow bytes per second
        if 'Flow Bytes/s' in row:
            flow_rate = row['Flow Bytes/s']
            if flow_rate < 1000:
                text_parts.append("low_byte_rate")
            elif flow_rate < 10000:
                text_parts.append("medium_byte_rate")
            else:
                text_parts.append("high_byte_rate")
        
        # Packet sizes
        if 'Packet Length Mean' in row:
            avg_size = row['Packet Length Mean']
            if avg_size < 100:
                text_parts.append("small_packets")
            elif avg_size < 500:
                text_parts.append("medium_packets")
            else:
                text_parts.append("large_packets")
        
        # Flag counts
        flag_cols = ['FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count']
        for flag_col in flag_cols:
            if flag_col in row and row[flag_col] > 0:
                flag_name = flag_col.split()[0].lower()
                text_parts.append(f"{flag_name}_flag_present")
        
        return " ".join(text_parts) if text_parts else "normal_traffic"

    def load_and_preprocess_data(self, csv_path):
        """Load and preprocess CSV data"""
        print("📊 Loading CSV data...")
        
        try:
            # Load the CSV file
            df = pd.read_csv(csv_path)
            print(f"✅ Loaded {len(df):,} samples")
            print(f"📋 Columns: {len(df.columns)}")
            
            # Handle missing values and infinities
            df = df.replace([np.inf, -np.inf], np.nan)
            
            # Check if 'Label' column exists
            if 'Label' not in df.columns:
                raise ValueError("Label column not found in dataset")
            
            # Remove rows with missing labels
            df = df.dropna(subset=['Label'])
            
            # Drop non-feature columns
            drop_cols = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp']
            feature_cols = [col for col in df.columns if col not in drop_cols and col != 'Label']
            
            # Fill missing values in feature columns
            df[feature_cols] = df[feature_cols].fillna(0)
            
            print(f"📈 Feature columns: {len(feature_cols)}")
            print(f"🎯 Label distribution:")
            label_counts = df['Label'].value_counts()
            for label, count in label_counts.items():
                if label == 'Benign' and count > 50000:
                    df = df.iloc[:50000]
                print(f"  {label}: {count:,}")
            
            # Convert numerical features to text
            print("🔄 Converting numerical features to text...")
            df['network_text'] = df[feature_cols].apply(self.numerical_to_text, axis=1)
            
            # Encode labels
            self.class_names = sorted(df['Label'].unique())
            df['attack_label'] = self.label_encoder.fit_transform(df['Label'])
            
            print(f"✅ Text conversion completed")
            print(f"📝 Sample text: {df['network_text'].iloc[0]}")
            
            return df[['network_text', 'attack_label', 'Label']]
            
        except Exception as e:
            print(f"❌ Error loading data: {e}")
            return None

    def prepare_datasets(self, df, test_size=0.2, val_size=0.1, max_samples_per_class=2000):
        """Prepare train, validation, and test datasets"""
        print("📊 Preparing datasets...")
        
        # Balance dataset to prevent memory issues
        print(f"⚖️ Balancing dataset (max {max_samples_per_class:,} samples per class)...")
        balanced_dfs = []
        
        for label in df['attack_label'].unique():
            class_df = df[df['attack_label'] == label]
            if len(class_df) > max_samples_per_class:
                class_df = class_df.sample(n=max_samples_per_class, random_state=42)
            balanced_dfs.append(class_df)
        
        balanced_df = pd.concat(balanced_dfs, ignore_index=True)
        print(f"📋 Balanced dataset: {len(balanced_df):,} samples")
        
        # Split data
        X = balanced_df['network_text'].values
        y = balanced_df['attack_label'].values
        
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Train-validation split
        X_train, X_val, y_train, y_val = train_test_split(
            X_train, y_train, test_size=val_size, random_state=42, stratify=y_train
        )
        
        print(f"📋 Dataset splits:")
        print(f"  Train: {len(X_train):,} samples")
        print(f"  Validation: {len(X_val):,} samples")
        print(f"  Test: {len(X_test):,} samples")
        
        return X_train, X_val, X_test, y_train, y_val, y_test

    def create_data_loaders(self, X_train, X_val, X_test, y_train, y_val, y_test, batch_size=8):
        """Create PyTorch data loaders"""
        print("⚙️ Creating data loaders...")
        
        train_dataset = NetworkTrafficDataset(X_train, y_train, self.tokenizer, max_length=64)
        val_dataset = NetworkTrafficDataset(X_val, y_val, self.tokenizer, max_length=64)
        test_dataset = NetworkTrafficDataset(X_test, y_test, self.tokenizer, max_length=64)
        
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
        test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
        
        return train_loader, val_loader, test_loader

    def initialize_model(self):
        """Initialize DistilBERT model"""
        num_classes = len(self.class_names)
        print(f"🤖 Initializing DistilBERT model with {num_classes} classes...")
        
        self.model = DistilBertForSequenceClassification.from_pretrained(
            'distilbert-base-uncased',
            num_labels=num_classes,
            output_attentions=False,
            output_hidden_states=False
        )
        
        self.model.to(device)
        print(f"✅ Model initialized")
        return self.model
    
    def plot_confusion_matrix(self, test_loader):
        """Plot confusion matrix for test data"""
        print("📊 Generating confusion matrix...")
        
        self.model.eval()
        predictions = []
        true_labels = []
        
        with torch.no_grad():
            for batch in tqdm(test_loader, desc="Evaluating for confusion matrix"):
                input_ids = batch['input_ids'].to(device)
                attention_mask = batch['attention_mask'].to(device)
                labels = batch['labels'].to(device)
                
                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask
                )
                
                logits = outputs.logits
                batch_predictions = torch.argmax(logits, dim=-1).cpu().numpy()
                
                predictions.extend(batch_predictions)
                true_labels.extend(labels.cpu().numpy())
        
        # Créer la matrice de confusion
        cm = confusion_matrix(true_labels, predictions)
        
        # Plot
        plt.figure(figsize=(12, 10))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=self.class_names, 
                    yticklabels=self.class_names)
        plt.title('Confusion Matrix - Network IDS Classification', fontsize=16)
        plt.xlabel('Predicted Label', fontsize=12)
        plt.ylabel('True Label', fontsize=12)
        plt.xticks(rotation=45, ha='right')
        plt.yticks(rotation=0)
        
        # Sauvegarder
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f'confusion_matrix_{timestamp}.png'
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"📊 Confusion matrix saved to: {filename}")
        
        plt.show()

    
    def plot_training_history(self, train_losses, val_losses, train_accuracies, val_accuracies, learning_rates):
        """Plot training history with multiple metrics"""
        plt.style.use('seaborn-v0_8-darkgrid')
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('Training History - DistilBERT Network IDS', fontsize=16)
        
        epochs = range(1, len(train_losses) + 1)
        
        # Plot 1: Loss curves
        axes[0, 0].plot(epochs, train_losses, 'b-', label='Training Loss', linewidth=2)
        axes[0, 0].plot(epochs, val_losses, 'r-', label='Validation Loss', linewidth=2)
        axes[0, 0].set_xlabel('Epoch')
        axes[0, 0].set_ylabel('Loss')
        axes[0, 0].set_title('Training and Validation Loss')
        axes[0, 0].legend()
        axes[0, 0].grid(True, alpha=0.3)
        
        # Plot 2: Accuracy curves
        axes[0, 1].plot(epochs, train_accuracies, 'b-', label='Training Accuracy', linewidth=2)
        axes[0, 1].plot(epochs, val_accuracies, 'r-', label='Validation Accuracy', linewidth=2)
        axes[0, 1].set_xlabel('Epoch')
        axes[0, 1].set_ylabel('Accuracy')
        axes[0, 1].set_title('Training and Validation Accuracy')
        axes[0, 1].legend()
        axes[0, 1].grid(True, alpha=0.3)
        axes[0, 1].set_ylim([0, 1])
        
        # Plot 3: Learning rate schedule
        axes[1, 0].plot(epochs, learning_rates, 'g-', linewidth=2)
        axes[1, 0].set_xlabel('Epoch')
        axes[1, 0].set_ylabel('Learning Rate')
        axes[1, 0].set_title('Learning Rate Schedule')
        axes[1, 0].grid(True, alpha=0.3)
        axes[1, 0].set_yscale('log')
        
        # Plot 4: Combined metrics
        ax1 = axes[1, 1]
        ax2 = ax1.twinx()
        
        line1 = ax1.plot(epochs, train_losses, 'b-', label='Train Loss', linewidth=2)
        line2 = ax1.plot(epochs, val_losses, 'b--', label='Val Loss', linewidth=2)
        line3 = ax2.plot(epochs, train_accuracies, 'r-', label='Train Acc', linewidth=2)
        line4 = ax2.plot(epochs, val_accuracies, 'r--', label='Val Acc', linewidth=2)
        
        ax1.set_xlabel('Epoch')
        ax1.set_ylabel('Loss', color='b')
        ax2.set_ylabel('Accuracy', color='r')
        ax1.set_title('Combined Training Metrics')
        ax1.tick_params(axis='y', labelcolor='b')
        ax2.tick_params(axis='y', labelcolor='r')
        
        # Combine legends
        lines = line1 + line2 + line3 + line4
        labels = [l.get_label() for l in lines]
        ax1.legend(lines, labels, loc='center right')
        
        plt.tight_layout()
        
        # Sauvegarder le graphique
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f'training_history_{timestamp}.png'
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"📊 Training history saved to: {filename}")
        
        plt.show()


    def evaluate_model_with_loss(self, data_loader):
        """Evaluate model performance with loss"""
        self.model.eval()
        predictions = []
        true_labels = []
        total_loss = 0
        
        with torch.no_grad():
            for batch in data_loader:
                input_ids = batch['input_ids'].to(device)
                attention_mask = batch['attention_mask'].to(device)
                labels = batch['labels'].to(device)
                
                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    labels=labels
                )
                
                loss = outputs.loss
                total_loss += loss.item()
                
                logits = outputs.logits
                predictions.extend(torch.argmax(logits, dim=-1).cpu().numpy())
                true_labels.extend(labels.cpu().numpy())
        
        avg_loss = total_loss / len(data_loader)
        accuracy = accuracy_score(true_labels, predictions)
        return avg_loss, accuracy


    def train_model(self, train_loader, val_loader, epochs=20, learning_rate=2e-5):
        """Train the DistilBERT model"""
        print("🚀 Starting DistilBERT training...")
        
        optimizer = AdamW(self.model.parameters(), lr=learning_rate, eps=1e-8)
        total_steps = len(train_loader) * epochs
        scheduler = get_linear_schedule_with_warmup(
            optimizer, num_warmup_steps=0, num_training_steps=total_steps
        )
        
        # Métriques pour les graphiques
        train_losses = []
        train_accuracies = []
        val_losses = []
        val_accuracies = []
        learning_rates = []
        
        for epoch in range(epochs):
            print(f"\n📊 Epoch {epoch + 1}/{epochs}")
            
            # Training phase
            self.model.train()
            total_train_loss = 0
            train_predictions = []
            train_labels = []
            
            progress_bar = tqdm(train_loader, desc="Training")
            for batch_idx, batch in enumerate(progress_bar):
                try:
                    input_ids = batch['input_ids'].to(device)
                    attention_mask = batch['attention_mask'].to(device)
                    labels = batch['labels'].to(device)
                    
                    optimizer.zero_grad()
                    
                    outputs = self.model(
                        input_ids=input_ids,
                        attention_mask=attention_mask,
                        labels=labels
                    )
                    
                    loss = outputs.loss
                    total_train_loss += loss.item()
                    
                    # Collecter les prédictions pour l'accuracy
                    logits = outputs.logits
                    predictions = torch.argmax(logits, dim=-1)
                    train_predictions.extend(predictions.cpu().numpy())
                    train_labels.extend(labels.cpu().numpy())
                    
                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                    optimizer.step()
                    scheduler.step()
                    
                    # Capturer le learning rate actuel
                    current_lr = scheduler.get_last_lr()[0]
                    
                    progress_bar.set_postfix({'loss': f'{loss.item():.4f}'})
                    
                except Exception as e:
                    print(f"❌ Error: {e}")
                    continue
            
            # Calculer les métriques d'entraînement
            avg_train_loss = total_train_loss / len(train_loader)
            train_accuracy = accuracy_score(train_labels, train_predictions)
            train_losses.append(avg_train_loss)
            train_accuracies.append(train_accuracy)
            learning_rates.append(scheduler.get_last_lr()[0])
            
            # Validation phase
            val_loss, val_accuracy = self.evaluate_model_with_loss(val_loader)
            val_losses.append(val_loss)
            val_accuracies.append(val_accuracy)
            
            print(f"📊 Training loss: {avg_train_loss:.4f}, Training accuracy: {train_accuracy:.4f}")
            print(f"📈 Validation loss: {val_loss:.4f}, Validation accuracy: {val_accuracy:.4f}")
        
        # Créer les graphiques
        self.plot_training_history(train_losses, val_losses, train_accuracies, val_accuracies, learning_rates)
        
        return train_losses, val_accuracies

    
    def save_model(self, filepath='network_ids_distilbert'):
        """Save model as TensorFlow Lite .model file"""
        print(f"💾 Converting to TensorFlow Lite format...")
        
        # First, save as SavedModel format temporarily
        temp_saved_model = 'temp_saved_model'
        
        # Create ExportArchive for proper SavedModel format
        export_archive = tf.keras.export.ExportArchive()
        export_archive.track(self.model)
        
        # Add serving endpoint with correct input signature
        export_archive.add_endpoint(
            name='serve',
            fn=self.model.call,
            input_signature=[tf.TensorSpec(shape=(1, self.input_dim), dtype=tf.float32)],
        )
        
        # Write out the SavedModel
        export_archive.write_out(temp_saved_model)
        
        # Convert to TensorFlow Lite
        converter = tf.lite.TFLiteConverter.from_saved_model(temp_saved_model)
        
        # Optional: Configure converter for optimization
        converter.optimizations = [tf.lite.Optimize.DEFAULT]
        converter.target_spec.supported_types = [tf.float16]  # For smaller model size
        
        # Convert the model
        tflite_model = converter.convert()
        
        # Save as .model file
        model_filepath = f"{filepath}.model"
        with open(model_filepath, 'wb') as f:
            f.write(tflite_model)
        
        # Clean up temporary SavedModel
        import shutil
        if os.path.exists(temp_saved_model):
            shutil.rmtree(temp_saved_model)
        
        print(f"✅ TFLite model saved to: {model_filepath}")
        print(f"📊 File size: {os.path.getsize(model_filepath) / 1024 / 1024:.2f} MB")
        
        return model_filepath


    def evaluate_model(self, data_loader):
        """Evaluate model performance"""
        self.model.eval()
        predictions = []
        true_labels = []
        
        with torch.no_grad():
            for batch in data_loader:
                input_ids = batch['input_ids'].to(device)
                attention_mask = batch['attention_mask'].to(device)
                labels = batch['labels'].to(device)
                
                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask
                )
                
                logits = outputs.logits
                predictions.extend(torch.argmax(logits, dim=-1).cpu().numpy())
                true_labels.extend(labels.cpu().numpy())
        
        accuracy = accuracy_score(true_labels, predictions)
        return accuracy

    def detailed_evaluation(self, test_loader):
        """Perform detailed evaluation"""
        print("📋 Performing detailed evaluation...")
        
        self.model.eval()
        predictions = []
        true_labels = []
        confidences = []
        
        with torch.no_grad():
            for batch in tqdm(test_loader, desc="Evaluating"):
                input_ids = batch['input_ids'].to(device)
                attention_mask = batch['attention_mask'].to(device)
                labels = batch['labels'].to(device)
                
                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask
                )
                
                logits = outputs.logits
                probs = torch.softmax(logits, dim=-1)
                
                batch_predictions = torch.argmax(logits, dim=-1).cpu().numpy()
                batch_confidences = torch.max(probs, dim=-1)[0].cpu().numpy()
                
                predictions.extend(batch_predictions)
                true_labels.extend(labels.cpu().numpy())
                confidences.extend(batch_confidences)
        
        accuracy = accuracy_score(true_labels, predictions)
        
        print(f"\n🎯 Test Accuracy: {accuracy:.4f}")
        print(f"📊 Average Confidence: {np.mean(confidences):.4f}")
        
        print("\n🎯 Detailed Classification Report:")
        print(classification_report(true_labels, predictions, target_names=self.class_names))
        
        return accuracy, confidences

def main():
    """Main execution function"""
    print("🚀 Network IDS Classification with DistilBERT")
    print("=" * 60)
    
    try:
        # Initialize classifier
        classifier = NetworkIDSClassifier()
        
        # Update this path to your actual CSV file
        CSV_PATH = './datasets/CIC-IDS/CICFlowMeter_out.csv'  # Update this path
        
        # Step 1: Load and preprocess data
        df = classifier.load_and_preprocess_data(CSV_PATH)
        if df is None:
            print("❌ Failed to load data. Please check your file path.")
            return
        
        # Step 2: Prepare datasets
        X_train, X_val, X_test, y_train, y_val, y_test = classifier.prepare_datasets(df)
        
        # Step 3: Create data loaders
        train_loader, val_loader, test_loader = classifier.create_data_loaders(
            X_train, X_val, X_test, y_train, y_val, y_test, batch_size=4
        )
        
        # Step 4: Initialize model
        model = classifier.initialize_model()
        
        # Step 5: Train model (augmenter le nombre d'epochs pour voir l'évolution)
        train_losses, val_accuracies = classifier.train_model(
            train_loader, val_loader, epochs=5, learning_rate=2e-5  # Plus d'epochs pour voir les courbes
        )
        
        # Step 6: Evaluate
        accuracy, confidences = classifier.detailed_evaluation(test_loader)
        
        # Step 7: Plot confusion matrix
        classifier.plot_confusion_matrix(test_loader)
        
        print(f"\n✅ Training completed successfully!")
        print(f"📈 Final Test Accuracy: {accuracy:.4f}")
        
        # Step 8: Save model
        classifier.save_model()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

# Résultat : 
# (ids) d:\Users\demo-labo-3\Desktop\ids>uv run modelTrainingFinBert.py
# Using device: cuda
# 🚀 Network IDS Classification with DistilBERT
# ============================================================
# 📊 Loading CSV data...
# ✅ Loaded 3,540,241 samples
# 📋 Columns: 84
# 📈 Feature columns: 76
# 🎯 Label distribution:
#   Benign: 3,450,658
#   Exploits: 30,951
#   Fuzzers: 29,613
#   Reconnaissance: 16,735
#   Generic: 4,632
#   DoS: 4,467
#   Shellcode: 2,102
#   Backdoor: 452
#   Analysis: 385
#   Worms: 246
# 🔄 Converting numerical features to text...
# ✅ Text conversion completed
# 📝 Sample text: long_duration few_forward_packets moderate_backward_packets high_byte_rate large_packets fin_flag_present syn_flag_present psh_flag_present ack_flag_present
# 📊 Preparing datasets...
# ⚖️ Balancing dataset (max 2,000 samples per class)...
# 📋 Balanced dataset: 5,177 samples
# 📋 Dataset splits:
#   Train: 3,726 samples
#   Validation: 415 samples
#   Test: 1,036 samples
# ⚙️ Creating data loaders...
# 🤖 Initializing DistilBERT model with 9 classes...
# Some weights of DistilBertForSequenceClassification were not initialized from the model checkpoint at distilbert-base-uncased and are newly initialized: ['classifier.bias', 'classifier.weight', 'pre_classifier.bias', 'pre_classifier.weight']
# You should probably TRAIN this model on a down-stream task to be able to use it for predictions and inference.
# ✅ Model initialized
# 🚀 Starting DistilBERT training...

# 📊 Epoch 1/2
# Training: 100%|███████████████████████████████████████████████████████████████████████████████████████████████| 932/932 [00:40<00:00, 23.17it/s, loss=1.2052]
# 📊 Training loss: 1.0741
# 🎯 Validation accuracy: 0.7133

# 📊 Epoch 2/2
# Training: 100%|███████████████████████████████████████████████████████████████████████████████████████████████| 932/932 [00:35<00:00, 26.62it/s, loss=0.7497]
# 📊 Training loss: 0.8905
# 🎯 Validation accuracy: 0.7205
# 📋 Performing detailed evaluation...
# Evaluating: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████| 259/259 [00:02<00:00, 101.69it/s]

# 🎯 Test Accuracy: 0.7403
# 📊 Average Confidence: 0.7992

# 🎯 Detailed Classification Report:
#                 precision    recall  f1-score   support

#       Backdoor       0.00      0.00      0.00         1
#         Benign       0.91      0.89      0.90       400
#            DoS       0.00      0.00      0.00        24
#       Exploits       0.73      0.40      0.52       183
#        Fuzzers       0.62      0.99      0.76       317
#        Generic       0.00      0.00      0.00        23
# Reconnaissance       0.59      0.29      0.39        76
#      Shellcode       0.00      0.00      0.00        11
#          Worms       0.00      0.00      0.00         1

#       accuracy                           0.74      1036
#      macro avg       0.32      0.29      0.29      1036
#   weighted avg       0.72      0.74      0.70      1036


# ✅ Training completed successfully!
# 🎯 Final Test Accuracy: 0.7403
