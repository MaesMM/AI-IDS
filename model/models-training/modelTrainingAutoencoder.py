import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, roc_curve
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import os

class AutoencoderNetworkIDS:
    """
    Autoencoder-based Network IDS using anomaly detection
    Particulièrement efficace pour détecter des attaques inconnues
    """
    
    def __init__(self):
        self.scaler = MinMaxScaler()
        self.encoder = None
        self.decoder = None
        self.autoencoder = None
        self.threshold = None
        self.input_dim = None
        
    def build_autoencoder(self, input_dim, encoding_dim=32):
        """
        Construire un autoencoder profond pour la détection d'anomalies
        """
        print("🏗️ Construction de l'autoencoder...")
        
        # Encoder
        encoder_input = keras.Input(shape=(input_dim,), name='encoder_input')
        
        # Architecture en entonnoir
        x = layers.Dense(256, activation='relu')(encoder_input)
        x = layers.BatchNormalization()(x)
        x = layers.Dropout(0.2)(x)
        
        x = layers.Dense(128, activation='relu')(x)
        x = layers.BatchNormalization()(x)
        x = layers.Dropout(0.2)(x)
        
        x = layers.Dense(64, activation='relu')(x)
        x = layers.BatchNormalization()(x)
        
        # Bottleneck (représentation compressée)
        encoded = layers.Dense(encoding_dim, activation='relu', name='encoded')(x)
        
        # Decoder
        x = layers.Dense(64, activation='relu')(encoded)
        x = layers.BatchNormalization()(x)
        
        x = layers.Dense(128, activation='relu')(x)
        x = layers.BatchNormalization()(x)
        x = layers.Dropout(0.2)(x)
        
        x = layers.Dense(256, activation='relu')(x)
        x = layers.BatchNormalization()(x)
        x = layers.Dropout(0.2)(x)
        
        # Reconstruction
        decoded = layers.Dense(input_dim, activation='sigmoid', name='decoded')(x)
        
        # Modèles
        self.encoder = keras.Model(encoder_input, encoded, name='encoder')
        self.decoder = keras.Model(encoded, decoded, name='decoder')
        self.autoencoder = keras.Model(encoder_input, decoded, name='autoencoder')
        
        # Compilation avec une loss spéciale pour la détection d'anomalies
        self.autoencoder.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='mse',  # Mean Squared Error pour la reconstruction
            metrics=['mae']  # Mean Absolute Error
        )
        
        return self.autoencoder
    
    def preprocess_for_autoencoder(self, df):
        """
        Prétraitement spécifique pour l'autoencoder
        """
        print("🔧 Prétraitement pour autoencoder...")
        
        # Colonnes à supprimer
        drop_cols = ['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 
                    'Protocol', 'Timestamp', 'Label']
        
        # Garder seulement les colonnes numériques
        feature_cols = [col for col in df.columns if col not in drop_cols]
        X = df[feature_cols].copy()
        
        # Gérer les valeurs infinies et manquantes
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(0)
        
        # Feature engineering statistique
        print("📊 Ajout de features statistiques...")
        
        # Ratios et statistiques
        if 'Total Fwd Packet' in X.columns and 'Total Bwd packets' in X.columns:
            X['packet_symmetry'] = np.abs(X['Total Fwd Packet'] - X['Total Bwd packets']) / (X['Total Fwd Packet'] + X['Total Bwd packets'] + 1)
        
        if 'Flow Duration' in X.columns:
            X['duration_log'] = np.log1p(X['Flow Duration'])
        
        # Détection de patterns anormaux
        flag_cols = [col for col in X.columns if 'Flag' in col]
        if flag_cols:
            X['flag_diversity'] = (X[flag_cols] > 0).sum(axis=1)
            X['flag_intensity'] = X[flag_cols].sum(axis=1)
        
        self.input_dim = X.shape[1]
        
        # Labels binaires
        y = None
        if 'Label' in df.columns:
            y = (df['Label'] != 'Benign').astype(int)
        
        return X, y
    
    def train_autoencoder(self, X_normal, X_val, epochs=50):
        """
        Entraîner l'autoencoder uniquement sur du trafic normal
        """
        print("🚀 Entraînement de l'autoencoder sur trafic normal...")
        
        # Callbacks avancés
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
        
        # Historique d'entraînement
        history = self.autoencoder.fit(
            X_normal, X_normal,  # Input = Output pour l'autoencoder
            validation_data=(X_val, X_val),
            epochs=epochs,
            batch_size=256,
            callbacks=callbacks,
            verbose=1
        )
        
        return history
    
    def calculate_reconstruction_error(self, X):
        """
        Calculer l'erreur de reconstruction pour chaque échantillon
        """
        predictions = self.autoencoder.predict(X, verbose=0)
        mse = np.mean(np.square(X - predictions), axis=1)
        return mse
    
    def determine_threshold(self, X_normal, percentile=95):
        """
        Déterminer le seuil optimal basé sur le trafic normal
        """
        print("🎯 Détermination du seuil optimal...")
        
        errors_normal = self.calculate_reconstruction_error(X_normal)
        self.threshold = np.percentile(errors_normal, percentile)
        
        print(f"📊 Seuil défini au {percentile}e percentile: {self.threshold:.6f}")
        
        return self.threshold
    
    def predict_anomalies(self, X):
        """
        Prédire les anomalies basées sur l'erreur de reconstruction
        """
        errors = self.calculate_reconstruction_error(X)
        predictions = (errors > self.threshold).astype(int)
        
        # Probabilités normalisées (0 = normal, 1 = anomalie)
        # Normalisation avec une fonction sigmoïde
        probabilities = 1 / (1 + np.exp(-(errors - self.threshold) / self.threshold))
        
        return predictions, probabilities, errors
    
    def plot_results(self, X_test, y_test, history):
        """
        Visualiser les résultats de l'autoencoder
        """
        print("📊 Génération des visualisations...")
        
        # Prédictions
        predictions, probabilities, errors = self.predict_anomalies(X_test)
        
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        
        # 1. Historique d'entraînement
        axes[0, 0].plot(history.history['loss'], label='Train Loss')
        axes[0, 0].plot(history.history['val_loss'], label='Val Loss')
        axes[0, 0].set_xlabel('Epoch')
        axes[0, 0].set_ylabel('Loss')
        axes[0, 0].set_title('Training History')
        axes[0, 0].legend()
        axes[0, 0].grid(True, alpha=0.3)
        
        # 2. Distribution des erreurs de reconstruction
        axes[0, 1].hist(errors[y_test == 0], bins=50, alpha=0.5, label='Normal', color='green', density=True)
        axes[0, 1].hist(errors[y_test == 1], bins=50, alpha=0.5, label='Attack', color='red', density=True)
        axes[0, 1].axvline(x=self.threshold, color='black', linestyle='--', label=f'Threshold')
        axes[0, 1].set_xlabel('Reconstruction Error')
        axes[0, 1].set_ylabel('Density')
        axes[0, 1].set_title('Reconstruction Error Distribution')
        axes[0, 1].legend()
        axes[0, 1].set_yscale('log')
        
        # 3. ROC Curve
        if y_test is not None:
            fpr, tpr, _ = roc_curve(y_test, probabilities)
            auc = roc_auc_score(y_test, probabilities)
            axes[0, 2].plot(fpr, tpr, 'b-', label=f'ROC (AUC = {auc:.3f})')
            axes[0, 2].plot([0, 1], [0, 1], 'r--')
            axes[0, 2].set_xlabel('False Positive Rate')
            axes[0, 2].set_ylabel('True Positive Rate')
            axes[0, 2].set_title('ROC Curve')
            axes[0, 2].legend()
            axes[0, 2].grid(True, alpha=0.3)
        
        # 4. Matrice de confusion
        from sklearn.metrics import confusion_matrix
        cm = confusion_matrix(y_test, predictions)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[1, 0])
        axes[1, 0].set_title('Confusion Matrix')
        axes[1, 0].set_xlabel('Predicted')
        axes[1, 0].set_ylabel('Actual')
        
        # 5. Scatter plot des erreurs
        sample_size = min(5000, len(errors))
        indices = np.random.choice(len(errors), sample_size, replace=False)
        
        axes[1, 1].scatter(range(sample_size), errors[indices], 
                          c=['green' if y == 0 else 'red' for y in y_test[indices]], 
                          alpha=0.5, s=10)
        axes[1, 1].axhline(y=self.threshold, color='black', linestyle='--')
        axes[1, 1].set_xlabel('Sample Index')
        axes[1, 1].set_ylabel('Reconstruction Error')
        axes[1, 1].set_title('Reconstruction Errors by Sample')
        
        # 6. Feature importance (variance dans l'espace latent)
        encoded_features = self.encoder.predict(X_test[:1000], verbose=0)
        feature_variance = np.var(encoded_features, axis=0)
        axes[1, 2].bar(range(len(feature_variance)), feature_variance)
        axes[1, 2].set_xlabel('Latent Feature')
        axes[1, 2].set_ylabel('Variance')
        axes[1, 2].set_title('Latent Space Feature Importance')
        
        plt.tight_layout()
        
        # Sauvegarder
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f'autoencoder_ids_results_{timestamp}.png'
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"✅ Résultats sauvegardés: {filename}")
        
        plt.show()
    
    def save_as_binary_model(self, filepath='autoencoder_ids'):
        """
        Sauvegarder en format .model binaire
        """
        print("💾 Sauvegarde du modèle autoencoder...")
        
        # Sauvegarder le modèle complet
        model_path = f"{filepath}.model"
        
        # Créer un modèle de prédiction simple qui retourne 0 ou 1
        input_layer = keras.Input(shape=(self.input_dim,))
        
        # Calculer l'erreur de reconstruction
        reconstructed = self.autoencoder(input_layer)
        error = tf.reduce_mean(tf.square(input_layer - reconstructed), axis=1, keepdims=True)
        
        # Convertir en probabilité d'anomalie
        # Utiliser une fonction sigmoïde centrée sur le seuil
        anomaly_score = tf.nn.sigmoid((error - self.threshold) / self.threshold)
        
        # Modèle final
        detection_model = keras.Model(inputs=input_layer, outputs=anomaly_score)
        
        # Sauvegarder
        detection_model.save(model_path, save_format='h5')
        
        # Sauvegarder les métadonnées
        import pickle
        metadata = {
            'threshold': self.threshold,
            'input_dim': self.input_dim,
            'scaler_params': {
                'min': self.scaler.data_min_,
                'max': self.scaler.data_max_
            }
        }
        
        with open(f"{filepath}_metadata.pkl", 'wb') as f:
            pickle.dump(metadata, f)
        
        print(f"✅ Modèle sauvegardé: {model_path}")
        print(f"📊 Taille: {os.path.getsize(model_path) / 1024 / 1024:.2f} MB")
        
        return model_path

def main():
    """Fonction principale"""
    print("🚀 Autoencoder Network IDS Detector")
    print("=" * 60)
    
    try:
        # Initialiser
        detector = AutoencoderNetworkIDS()
        
        # Charger les données
        csv_path = './datasets/CIC-IDS/CICFlowMeter_out.csv'
        print(f"📊 Chargement des données...")
        df = pd.read_csv(csv_path, nrows=100000)
        
        # Prétraitement
        X, y = detector.preprocess_for_autoencoder(df)
        
        # Normalisation (importante pour l'autoencoder)
        X_scaled = detector.scaler.fit_transform(X)
        
        # Séparer les données normales pour l'entraînement
        if y is not None:
            X_normal = X_scaled[y == 0]
            X_anomaly = X_scaled[y == 1]
            
            print(f"📊 Distribution des données:")
            print(f"   Normal: {len(X_normal):,}")
            print(f"   Anomalie: {len(X_anomaly):,}")
        else:
            X_normal = X_scaled
        
        # Split pour l'entraînement
        X_train, X_test = train_test_split(X_normal, test_size=0.2, random_state=42)
        X_train, X_val = train_test_split(X_train, test_size=0.2, random_state=42)
        
        # Construire l'autoencoder
        detector.build_autoencoder(detector.input_dim, encoding_dim=32)
        detector.autoencoder.summary()
        
        # Entraîner
        history = detector.train_autoencoder(X_train, X_val, epochs=30)
        
        # Déterminer le seuil
        detector.determine_threshold(X_val, percentile=95)
        
        # Test sur l'ensemble complet
        if y is not None:
            # Créer un ensemble de test mixte
            X_test_mixed = np.vstack([X_test[:1000], X_anomaly[:1000]])
            y_test_mixed = np.hstack([np.zeros(1000), np.ones(1000)])
            
            # Mélanger
            indices = np.random.permutation(len(X_test_mixed))
            X_test_mixed = X_test_mixed[indices]
            y_test_mixed = y_test_mixed[indices]
            
            # Évaluation
            predictions, probabilities, errors = detector.predict_anomalies(X_test_mixed)
            
            print("\n📈 Rapport de classification:")
            print(classification_report(y_test_mixed, predictions, 
                                      target_names=['Normal', 'Anomalie'],
                                      digits=4))
            
            # Visualisations
            detector.plot_results(X_test_mixed, y_test_mixed, history)
        
        # Sauvegarder
        model_path = detector.save_as_binary_model('autoencoder_network_ids')
        
        print(f"\n✅ Entraînement terminé!")
        print(f"📁 Modèle sauvegardé: {model_path}")
        
    except Exception as e:
        print(f"❌ Erreur: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
