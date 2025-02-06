import tensorflow as tf
from tensorflow.keras import layers, models, optimizers

def create_model(inputLen):
    model = tf.keras.Sequential([
        layers.Input(shape=[inputLen]),

        # Ajout de couches denses intermédiaires
        layers.Dense(32, activation='relu'),
        # layers.BatchNormalization(),
        # layers.Dropout(0.2),

        # Couche de sortie
        layers.Dense(1, activation='sigmoid')
    ])

    model.compile(
        loss='binary_crossentropy',
        optimizer= optimizers.Adam(learning_rate=1e-4,  clipnorm=1.0),
        metrics=['accuracy']
    )

    model.summary()
    return model


def train_model(model, X_train, y_train):
    print("Trainning")
    print(f"X_train: {X_train}")
    print(f"Y_train: {y_train}")
    history = model.fit(
        X_train, y_train,
        epochs=20,
        batch_size=32,
        validation_split=0.2,
        # callbacks=[
        #     tf.keras.callbacks.EarlyStopping(
        #         # monitor='val_loss',
        #         patience=3,
        #         restore_best_weights=True
        #     )
        # ]
    )
