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
        """Advanced preprocessing with improved error handling"""
        print("🔧 Advanced preprocessing...")
        
        # Define columns to drop
        drop_cols = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp']
        
        if 'Label' in df.columns:
            # For SnortML, we need binary classification
            # Convert to binary: Benign (0) vs Attack (1)
            unique_labels = df['Label'].unique()
            print(f"📊 Found {len(unique_labels)} unique labels: {list(unique_labels)}")
            
            # Binary mapping: Benign = 0, Everything else = 1
            y = (df['Label'] != 'Benign').astype(np.float32)
            
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
        
        # Store input dimension
        self.input_dim = X.shape[1]
        
        return X, y
    
    def balance_dataset(self, X, y, strategy='hybrid'):
        """Balance dataset for binary classification"""
        print("⚖️ Balancing dataset...")
        
        # Get class distribution
        unique, counts = np.unique(y, return_counts=True)
        class_distribution = dict(zip(unique, counts))
        
        print("📊 Original distribution:")
        print(f"  Benign (0): {class_distribution.get(0, 0):,} samples")
        print(f"  Attack (1): {class_distribution.get(1, 0):,} samples")
        
        if strategy == 'hybrid':
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
            print(f"  Class {int(label)}: {count:,} samples")
        
        return X_balanced, y_balanced
    
    def build_snortml_model(self):
        """Build a TensorFlow model compatible with SnortML requirements"""
        print("🏗️ Building SnortML-compatible TensorFlow model...")
        
        # Input layer - single tensor, float32
        inputs = keras.Input(shape=(self.input_dim,), dtype=tf.float32, name='input')
        
        # Normalization layer
        x = layers.BatchNormalization()(inputs)
        
        # Dense layers with dropout for regularization
        x = layers.Dense(256, activation='relu')(x)
        x = layers.Dropout(0.3)(x)
        
        x = layers.Dense(128, activation='relu')(x)
        x = layers.Dropout(0.3)(x)
        
        x = layers.Dense(64, activation='relu')(x)
        x = layers.Dropout(0.2)(x)
        
        x = layers.Dense(32, activation='relu')(x)
        
        # Output layer - single element, float32
        # Using sigmoid for binary classification probability
        outputs = layers.Dense(1, activation='sigmoid', dtype=tf.float32, name='output')(x)
        
        # Create model
        model = keras.Model(inputs=inputs, outputs=outputs)
        
        # Compile with binary crossentropy
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall()]
        )
        
        return model
    
    def build_lstm_snortml_model(self):
        """Build an LSTM model similar to the SnortML example"""
        print("🏗️ Building LSTM SnortML-compatible model...")
        
        # For LSTM, we need to reshape input as sequences
        # Using a sliding window approach
        sequence_length = 10  # Process 10 features at a time
        feature_groups = self.input_dim // sequence_length
        
        # Input layer
        inputs = keras.Input(shape=(self.input_dim,), dtype=tf.float32)
        
        # Reshape for LSTM
        x = layers.Reshape((sequence_length, feature_groups))(inputs)
        
        # LSTM layers
        x = layers.LSTM(64, return_sequences=True)(x)
        x = layers.LSTM(32)(x)
        
        # Dense layers
        x = layers.Dense(16, activation='relu')(x)
        x = layers.Dropout(0.2)(x)
        
        # Output layer - single element
        outputs = layers.Dense(1, activation='sigmoid', dtype=tf.float32)(x)
        
        model = keras.Model(inputs=inputs, outputs=outputs)
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def train_tensorflow_model(self, X_train, y_train, X_val, y_val, model_type='dense'):
        """Train the TensorFlow model"""
        print(f"🚀 Training {model_type} TensorFlow model...")
        
        # Build model
        if model_type == 'lstm':
            self.model = self.build_lstm_snortml_model()
        else:
            self.model = self.build_snortml_model()
        
        # Print model summary
        self.model.summary()
        
        # Callbacks
        callbacks = [
            keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True
            ),
            keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
                min_lr=0.00001
            )
        ]
        
        # Train model
        history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=100,
            batch_size=256,
            callbacks=callbacks,
            verbose=1
        )
        
        return history
    
    # In the save_snortml_model method, update the save paths:

    def save_snortml_model(self, filepath='snortml_ids_model'):
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

        



def main():
    """Main function for SnortML model creation"""
    print("🚀 SnortML Network IDS Model Builder")
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
                # Load only a subset for faster training if needed
                df = pd.read_csv(csv_path, nrows=100000)  # Adjust as needed
                break
        
        if df is None:
            print("❌ Dataset not found. Please ensure the CSV file exists.")
            return
        
        print(f"✅ Loaded {len(df):,} samples with {df.shape[1]} features")
        
        # Preprocessing
        X, y = classifier.advanced_preprocessing(df)
        print(f"📊 After preprocessing: {X.shape[1]} features")
        
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
        print(f"  Train: {len(X_train):,}")
        print(f"  Validation: {len(X_val):,}")
        print(f"  Test: {len(X_test):,}")
        
        # Train model (choose 'dense' or 'lstm')
        history = classifier.train_tensorflow_model(
            X_train, y_train, X_val, y_val, model_type='dense'
        )
        
        # Evaluate on test set
        print("\n📊 Evaluating on test set...")
        test_loss, test_acc, test_precision, test_recall = classifier.model.evaluate(
            X_test, y_test, verbose=0
        )
        
        print(f"Test Accuracy: {test_acc:.4f}")
        print(f"Test Precision: {test_precision:.4f}")
        print(f"Test Recall: {test_recall:.4f}")
        
        # Get predictions for detailed report
        y_pred_proba = classifier.model.predict(X_test)
        y_pred = (y_pred_proba > 0.5).astype(int).flatten()
        
        print("\n📊 Classification Report:")
        print(classification_report(
            y_test, y_pred, 
            target_names=['Benign', 'Attack'],
            digits=4
        ))
        
        # Save model
        model_path = classifier.save_snortml_model('snortml_ids_model')
        
        print(f"\n✅ Model successfully created and saved!")
        print(f"📁 Model location: {model_path}")
        print("\n🔧 To use with SnortML:")
        print("1. Copy the model file to your Snort configuration directory")
        print("2. Configure snort_ml_engine in your Snort config")
        print("3. Use the http_param_model type for HTTP traffic analysis")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
