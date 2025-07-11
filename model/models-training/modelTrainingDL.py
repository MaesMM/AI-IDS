import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
import os

class SnortMLNetworkIDSClassifier:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = None
        self.label_mapping = {}
        self.input_dim = None
        
    def advanced_preprocessing(self, df):
        """Advanced preprocessing with improved error handling and binary label conversion"""
        print("🔧 Advanced preprocessing...")
        
        # Define columns to drop
        drop_cols = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp']
        
        if 'Label' in df.columns:
            # Get unique labels before conversion
            unique_labels = df['Label'].unique()
            print(f"📊 Found {len(unique_labels)} unique labels: {list(unique_labels)}")
            
            # Create binary labels: 0 for Benign, 1 for any attack
            # Handle different label formats (case-insensitive)
            df['Label'] = df['Label'].astype(str).str.strip().str.lower()
            
            # Binary mapping
            benign_labels = ['benign', 'normal', 'legitimate', '0']
            y = np.zeros(len(df), dtype=np.float32)
            
            # Mark all non-benign as attacks (1)
            for idx, label in enumerate(df['Label']):
                if label not in benign_labels:
                    y[idx] = 1.0
            
            # Print label distribution
            print(f"📊 Binary label distribution:")
            print(f"  Benign (0): {np.sum(y == 0):,} samples")
            print(f"  Attack (1): {np.sum(y == 1):,} samples")
            
            # Store label mapping for reference
            self.label_mapping = {
                'benign': 0,
                'attack': 1
            }
            
            # Drop unnecessary columns
            existing_drop_cols = [col for col in drop_cols if col in df.columns]
            X = df.drop(['Label'] + existing_drop_cols, axis=1)
        else:
            raise ValueError("Label column not found in the dataset!")
        
        # Data cleaning
        print("🧹 Cleaning data...")
        X = X.replace([np.inf, -np.inf], np.nan)
        
        # Fill NaN with median for numeric columns
        numeric_columns = X.select_dtypes(include=[np.number]).columns
        X[numeric_columns] = X[numeric_columns].fillna(X[numeric_columns].median())
        
        # Feature Engineering
        print("⚙️ Engineering features...")
        X['packet_size_ratio'] = X.get('Fwd Packet Length Mean', 0) / (X.get('Bwd Packet Length Mean', 1) + 1)
        X['flow_efficiency'] = X.get('Flow Bytes/s', 0) / (X.get('Flow Duration', 1) + 1)
        X['bidirectional_ratio'] = X.get('Total Fwd Packet', 0) / (X.get('Total Bwd packets', 1) + 1)
        
        # Replace any remaining inf values
        X = X.replace([np.inf, -np.inf], 0)
        
        # Ensure all values are numeric
        X = X.apply(pd.to_numeric, errors='coerce').fillna(0)
        
        # Store input dimension
        self.input_dim = X.shape[1]
        print(f"📊 Input dimension: {self.input_dim}")
        
        # Final verification of labels
        assert np.all(np.isin(y, [0, 1])), "Labels must be binary (0 or 1)"
        print(f"✅ Labels verified: all values are binary (0 or 1)")
        
        return X, y
    
    def balance_dataset(self, X, y, strategy='hybrid'):
        """Balance dataset for binary classification"""
        print("⚖️ Balancing dataset...")
        
        # Ensure y is binary
        assert np.all(np.isin(y, [0, 1])), "Labels must be binary before balancing"
        
        # Get class distribution
        unique, counts = np.unique(y, return_counts=True)
        class_distribution = dict(zip(unique, counts))
        
        print("📊 Original distribution:")
        print(f"  Benign (0): {class_distribution.get(0, 0):,} samples ({class_distribution.get(0, 0)/len(y)*100:.1f}%)")
        print(f"  Attack (1): {class_distribution.get(1, 0):,} samples ({class_distribution.get(1, 0)/len(y)*100:.1f}%)")
        
        if strategy == 'hybrid':
            # Calculate imbalance ratio
            imbalance_ratio = max(counts) / min(counts) if min(counts) > 0 else float('inf')
            print(f"📊 Imbalance ratio: {imbalance_ratio:.2f}:1")
            
            # Undersample majority class if needed
            max_samples = 50000  # Limit for training efficiency
            
            if counts[0] > max_samples or counts[1] > max_samples:
                undersample_strategy = {}
                for class_label, count in class_distribution.items():
                    if count > max_samples:
                        undersample_strategy[class_label] = max_samples
                
                undersampler = RandomUnderSampler(
                    sampling_strategy=undersample_strategy,
                    random_state=42
                )
                X_balanced, y_balanced = undersampler.fit_resample(X, y)
            else:
                # Use SMOTE to balance classes
                smote = SMOTE(random_state=42, k_neighbors=5)
                X_balanced, y_balanced = smote.fit_resample(X, y)
        else:
            X_balanced, y_balanced = X, y
        
        print("📊 Balanced distribution:")
        unique_bal, counts_bal = np.unique(y_balanced, return_counts=True)
        for label, count in zip(unique_bal, counts_bal):
            label_name = "Benign" if label == 0 else "Attack"
            percentage = count/len(y_balanced)*100
            print(f"  {label_name} ({int(label)}): {count:,} samples ({percentage:.1f}%)")
        
        return X_balanced, y_balanced
    
    def build_cnn_lstm_model(self):
        """Build a CNN-LSTM hybrid model for network intrusion detection"""
        print("🏗️ Building CNN-LSTM hybrid model...")
        
        # Calculate dimensions for reshaping
        sequence_length = 10  # Number of time steps
        n_features = self.input_dim // sequence_length
        
        # If not perfectly divisible, adjust
        if self.input_dim % sequence_length != 0:
            n_features = self.input_dim // sequence_length + 1
            padded_dim = n_features * sequence_length
        else:
            padded_dim = self.input_dim
        
        # Input layer
        inputs = keras.Input(shape=(self.input_dim,), dtype=tf.float32, name='input')
        
        # Pad if necessary
        if padded_dim > self.input_dim:
            x = layers.ZeroPadding1D(padding=(0, padded_dim - self.input_dim))(
                layers.Reshape((self.input_dim, 1))(inputs)
            )
            x = layers.Reshape((padded_dim,))(x)
        else:
            x = inputs
        
        # Reshape for CNN: (batch, height, width, channels)
        x = layers.Reshape((sequence_length, n_features, 1))(x)
        
        # CNN layers for feature extraction
        x = layers.Conv2D(32, kernel_size=(3, 3), padding='same', activation='relu')(x)
        x = layers.BatchNormalization()(x)
        x = layers.MaxPooling2D(pool_size=(2, 2), padding='same')(x)
        x = layers.Dropout(0.25)(x)
        
        x = layers.Conv2D(64, kernel_size=(3, 3), padding='same', activation='relu')(x)
        x = layers.BatchNormalization()(x)
        x = layers.MaxPooling2D(pool_size=(2, 2), padding='same')(x)
        x = layers.Dropout(0.25)(x)
        
        x = layers.Conv2D(128, kernel_size=(3, 3), padding='same', activation='relu')(x)
        x = layers.BatchNormalization()(x)
        x = layers.GlobalAveragePooling2D()(x)
        
        # Reshape for LSTM
        x = layers.Reshape((8, 16))(x)
        
        # LSTM layers
        x = layers.LSTM(64, return_sequences=True, dropout=0.2)(x)
        x = layers.LSTM(32, dropout=0.2)(x)
        
        # Dense layers
        x = layers.Dense(64, activation='relu')(x)
        x = layers.Dropout(0.3)(x)
        x = layers.Dense(32, activation='relu')(x)
        x = layers.Dropout(0.2)(x)
        
        # Output layer - binary classification
        outputs = layers.Dense(1, activation='sigmoid', dtype=tf.float32, name='output')(x)
        
        # Create model
        model = keras.Model(inputs=inputs, outputs=outputs)
        
        # Compile with binary crossentropy
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', 
                    keras.metrics.Precision(name='precision'),
                    keras.metrics.Recall(name='recall'),
                    keras.metrics.AUC(name='auc')]
        )
        
        return model
    
    def build_alternative_cnn_lstm_model(self):
        """Alternative CNN-LSTM architecture with 1D convolutions"""
        print("🏗️ Building alternative CNN-LSTM model with 1D convolutions...")
        
        # Input layer
        inputs = keras.Input(shape=(self.input_dim,), dtype=tf.float32, name='input')
        
        # Reshape for 1D CNN
        x = layers.Reshape((self.input_dim, 1))(inputs)
        
        # 1D CNN layers
        x = layers.Conv1D(64, kernel_size=5, padding='same', activation='relu')(x)
        x = layers.BatchNormalization()(x)
        x = layers.MaxPooling1D(pool_size=2)(x)
        x = layers.Dropout(0.25)(x)
        
        x = layers.Conv1D(128, kernel_size=5, padding='same', activation='relu')(x)
        x = layers.BatchNormalization()(x)
        x = layers.MaxPooling1D(pool_size=2)(x)
        x = layers.Dropout(0.25)(x)
        
        x = layers.Conv1D(256, kernel_size=3, padding='same', activation='relu')(x)
        x = layers.BatchNormalization()(x)
        x = layers.MaxPooling1D(pool_size=2)(x)
        x = layers.Dropout(0.25)(x)
        
        # LSTM layers
        x = layers.LSTM(128, return_sequences=True, dropout=0.2)(x)
        x = layers.LSTM(64, dropout=0.2)(x)
        
        # Dense layers
        x = layers.Dense(128, activation='relu')(x)
        x = layers.Dropout(0.3)(x)
        x = layers.Dense(64, activation='relu')(x)
        x = layers.Dropout(0.2)(x)
        
        # Output layer - binary classification
        outputs = layers.Dense(1, activation='sigmoid', dtype=tf.float32, name='output')(x)
        
        # Create model
        model = keras.Model(inputs=inputs, outputs=outputs)
        
        # Compile
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy',
                    keras.metrics.Precision(name='precision'),
                    keras.metrics.Recall(name='recall'),
                    keras.metrics.AUC(name='auc')]
        )
        
        return model
    
    def train_tensorflow_model(self, X_train, y_train, X_val, y_val, model_type='cnn_lstm_1d'):
        """Train the TensorFlow model"""
        print(f"🚀 Training {model_type} TensorFlow model...")
        
        # Verify labels are binary
        assert np.all(np.isin(y_train, [0, 1])), "Training labels must be binary"
        assert np.all(np.isin(y_val, [0, 1])), "Validation labels must be binary"
        
        # Build model based on type
        if model_type == 'cnn_lstm':
            self.model = self.build_cnn_lstm_model()
        elif model_type == 'cnn_lstm_1d':
            self.model = self.build_alternative_cnn_lstm_model()
        else:
            self.model = self.build_snortml_model()
        
        # Print model summary
        self.model.summary()
        
        # Callbacks
        callbacks = [
            keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True,
                verbose=1
            ),
            keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
                min_lr=0.00001,
                verbose=1
            ),
            keras.callbacks.ModelCheckpoint(
                'best_cnn_lstm_model.h5',
                monitor='val_auc',
                save_best_only=True,
                mode='max',
                verbose=1
            )
        ]
        
        # Class weights for imbalanced data
        class_weights = {0: 1.0, 1: 1.0}  # Adjust if needed
        
        # Train model
        history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=40,
            batch_size=256,
            callbacks=callbacks,
            class_weight=class_weights,
            verbose=1
        )
        
        return history
    
    def build_snortml_model(self):
        """Original dense model for comparison"""
        print("🏗️ Building SnortML-compatible TensorFlow model...")
        
        inputs = keras.Input(shape=(self.input_dim,), dtype=tf.float32, name='input')
        x = layers.BatchNormalization()(inputs)
        x = layers.Dense(256, activation='relu')(x)
        x = layers.Dropout(0.3)(x)
        x = layers.Dense(128, activation='relu')(x)
        x = layers.Dropout(0.3)(x)
        x = layers.Dense(64, activation='relu')(x)
        x = layers.Dropout(0.2)(x)
        x = layers.Dense(32, activation='relu')(x)
        outputs = layers.Dense(1, activation='sigmoid', dtype=tf.float32, name='output')(x)
        
        model = keras.Model(inputs=inputs, outputs=outputs)
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall()]
        )
        
        return model
    
    def save_snortml_model(self, filepath='snortml_ids_model_DL'):
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
        
        # Configure converter for optimization
        converter.optimizations = [tf.lite.Optimize.DEFAULT]
        converter.target_spec.supported_types = [tf.float16]
        
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


def main():
    """Main function for SnortML model creation"""
    print("🚀 SnortML Network IDS Model Builder with CNN-LSTM")
    print("=" * 60)
    
    try:
        # Initialize classifier
        classifier = SnortMLNetworkIDSClassifier()
        
        # Load data
        possible_paths = [
            './datasets/CIC-IDS/CICFlowMeter_out.csv',
            './CICFlowMeter_out.csv',
            'CICFlowMeter_out.csv'
        ]
        
        df = None
        for csv_path in possible_paths:
            if os.path.exists(csv_path):
                print(f"📊 Loading data from {csv_path}")
                df = pd.read_csv(csv_path, nrows=10000000)  # Adjust as needed
                break
        
        if df is None:
            print("❌ Dataset not found. Please ensure the CSV file exists.")
            return
        
        print(f"✅ Loaded {len(df):,} samples with {df.shape[1]} features")
        
        # Preprocessing with binary labels
        X, y = classifier.advanced_preprocessing(df)
        print(f"📊 After preprocessing: {X.shape[1]} features")
        
        # Verify binary labels
        print(f"✅ Label verification: min={y.min()}, max={y.max()}")
        assert y.min() == 0 and y.max() == 1, "Labels must be 0 or 1"
        
        # Balance dataset
        X_balanced, y_balanced = classifier.balance_dataset(X, y, strategy='hybrid')
        
        # Scale features
        print("📏 Scaling features...")
        X_scaled = classifier.scaler.fit_transform(X_balanced).astype(np.float32)
        
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y_balanced, test_size=0.2, random_state=42, stratify=y_balanced
        )
        
        X_train, X_val, y_train, y_val = train_test_split(
            X_train, y_train, test_size=0.15, random_state=42, stratify=y_train
        )
        
        print(f"📋 Dataset splits:")
        print(f"  Train: {len(X_train):,} (Benign: {np.sum(y_train==0):,}, Attack: {np.sum(y_train==1):,})")
        print(f"  Validation: {len(X_val):,} (Benign: {np.sum(y_val==0):,}, Attack: {np.sum(y_val==1):,})")
        print(f"  Test: {len(X_test):,} (Benign: {np.sum(y_test==0):,}, Attack: {np.sum(y_test==1):,})")
        
        # Train CNN-LSTM model
        history = classifier.train_tensorflow_model(
            X_train, y_train, X_val, y_val, model_type='cnn_lstm_1d'
        )
        
        # Evaluate on test set
        print("\n📊 Evaluating on test set...")
        test_metrics = classifier.model.evaluate(X_test, y_test, verbose=0)
        
        # Extract metrics
        metric_names = classifier.model.metrics_names
        for name, value in zip(metric_names, test_metrics):
            print(f"{name.capitalize()}: {value:.4f}")
        
        # Get predictions for detailed report
        y_pred_proba = classifier.model.predict(X_test)
        y_pred = (y_pred_proba > 0.5).astype(int).flatten()
        
        print("\n📊 Classification Report:")
        print(classification_report(
            y_test, y_pred, 
            target_names=['Benign (0)', 'Attack (1)'],
            digits=4
        ))
        
        # Save model
        model_path = classifier.save_snortml_model('snortml_cnn_lstm_ids_model')
        
        print(f"\n✅ CNN-LSTM model successfully created and saved!")
        print(f"📁 Model location: {model_path}")
        print(f"🏷️ Binary classification: 0=Benign, 1=Attack")
        print("\n🔧 To use with SnortML:")
        print("1. Copy the model file to your Snort configuration directory")
        print("2. Configure snort_ml_engine in your Snort config")
        print("3. The model outputs probability of attack (0-1)")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
