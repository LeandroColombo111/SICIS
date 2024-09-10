import tensorflow as tf
from dotenv import load_dotenv
import os 
import hashlib
import requests 
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
from imblearn.over_sampling import SMOTE
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense
import seaborn as sns
import matplotlib.pyplot as plt




"""
1. define conjunto de datos de entrenamiento 
2. define arquitectura de la Red neuronal
3. configurar el proceso de aprendizaje, seleccion de funcion de error, funcion de optimizacion y diferentes metricas para monitorizar 
4. entrenar la Red con mi conjunto de datos de entrenamiento.
"""
class MalwareDetector:
    def __init__(self, model_path=r'C:\Users\leand\OneDrive\Desktop\SICIS\Modelo\sicis_destructor.h5'):
        if model_path:
            self.model = load_model(model_path)
        else:
            self.model = None
        self.scaler = StandardScaler()
        self.smote = SMOTE(random_state=42)

    def load_data(self, train_path, test_path):
        self.train_data = pd.read_csv(train_path)
        self.test_data = pd.read_csv(test_path)
        self.X_train = self.train_data.drop('Class', axis=1)
        self.y_train = self.train_data['Class']
        self.X_test = self.test_data.values

    def preprocess_data(self):
        X_scaled = self.scaler.fit_transform(self.X_train)
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X_scaled, self.y_train, test_size=0.2, random_state=42)
        self.X_train_smote, self.y_train_smote = self.smote.fit_resample(
            self.X_train, self.y_train)

    def build_model(self):
        if self.model is None:
            self.model = Sequential()
            self.model.add(Dense(512, activation='relu', input_shape=(self.X_train_smote.shape[1],)))
            self.model.add(Dense(256, activation='relu'))
            self.model.add(Dense(128, activation='relu'))
            self.model.add(Dense(9, activation='softmax'))
            self.model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])

    def train_model(self, epochs=50, batch_size=32):
        if self.model is None:
            print("No hay modelo para entrenar. Por favor, primero construye el modelo.")
            return

        self.y_train_smote_adjusted = self.y_train_smote - 1
        self.model.fit(self.X_train_smote, self.y_train_smote_adjusted, epochs=epochs, batch_size=batch_size, validation_split=0.2)

    def evaluate_model(self):
        if self.model is None:
            print("No hay modelo para evaluar.")
            return

        y_pred = self.model.predict(self.X_test)
        y_pred_classes = np.argmax(y_pred, axis=1)
        cm = confusion_matrix(self.y_test-1, y_pred_classes)
        sns.heatmap(cm, annot=True, fmt='d')
        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.show()

        precision = precision_score(self.y_test-1, y_pred_classes, average='weighted')
        recall = recall_score(self.y_test-1, y_pred_classes, average='weighted')
        f1 = f1_score(self.y_test-1, y_pred_classes, average='weighted')
        print("Precisión: {:.2f}".format(precision))
        print("Recuperación: {:.2f}".format(recall))
        print("Puntuación F1: {:.2f}".format(f1))



class MalwareDetector:
    def __init__(self, model_path):

        self.deep_learning_analyzer = DeepLearningAnalyzer(model_path)
        self.known_malware_signatures = self.load_malware_signatures()

    def consult_misp(self, filepath):
        """"Consulta la API MISP para objetes IoCs relacionados con el archivo"""
        misp_url = os.getenv('MISP_URL')
        api_key = os.getenv('MISP_KEY')
        headers = {'Autorization':api_key}

        #Definir como realizar la consulta 
        #Podria calcular el hash del archivo y buscarlo en MISP
        file_hash = self.calculate_file_hash(filepath)

        response = requests.get(f"{misp_url}/attributes/restSearch", headers=headers, json={"value": file_hash})

        if response.status_code == 200:
            # Procesa la respuesta
            # Por ejemplo, si la respuesta contiene IoCs relacionados, considera el archivo como malicioso
            data = response.json()
            if data["response"]["Attribute"]:  # Asumiendo que la respuesta contiene un campo 'Attribute'
                return True
        return False

    def load_malware_signatures(self):
        # Cargar firmas de malware desde un archivo o base de datos
        # Por ejemplo, retornar un conjunto de hashes de malware conocido
        return set(["123abc...", "456def...", ...])
    
    def analyze(self, filepath):
        # Primero, consulta MISP
        if self.consult_misp(filepath):
            return True

        # Luego, verifica las firmas conocidas
        if self.check_signature(filepath):
            return True

        # Finalmente, utiliza análisis con deep learning
        return self.deep_learning_analyzer.analyze(filepath)
    
    def check_signature(self, filepath):
        file_hash = self.calculate_file_hash(filepath)
        return file_hash in self.known_malware_signatures
    
    def calculate_file_hash(self, filepath):
        # Calcular el hash SHA256 del archivo
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as file:
                buf = file.read()
                hasher.update(buf)
            return hasher.hexdigest()
        except IOError:
            # Manejar el error si el archivo no se puede leer
            return ""

class DeepLearningAnalyzer:
    def __init__(self, scaler):
        self.model = 'C:\\Users\\leand\\OneDrive\\Desktop\\SICIS\\Modelo\\sicis_destructor.h5'
        self.scaler = scaler
    def analyze(self, filepath):
        processed_data = self.preprocess_file(filepath)
        prediction = self.model.predict(processed_data)
        return self.interpret_prediction(prediction)


    def preprocess_file(self, filepath):
        # Aquí debes implementar la lógica para convertir tu archivo en un conjunto de características numéricas
        # Por ejemplo:
        features = self.extract_features_from_file(filepath)  # Esta función debe ser definida por ti

        # Aplicar el mismo escalado que se usó durante el entrenamiento
        scaled_features = self.scaler.transform([features])
        return scaled_features

    def extract_features_from_file(self, filepath):
        data = pd.read_csv(filepath)
        features = data[...]


        return features

    def interpret_prediction(self, prediction):
        # Interpretar la salida del modelo
        # Por ejemplo, si es un modelo de clasificación binaria, podrías hacer algo como:
        threshold = 0.5  # Define un umbral
        return prediction[0] > threshold



# Uso
antivirus = AntivirusBase()
antivirus.scan_file('ruta/a/archivo/sospechoso')




detector_con_modelo = MalwareDetector(model_path='tu_modelo.h5')
detector_con_modelo.load_data('path_to_train.csv', 'path_to_test.csv')
detector_con_modelo.preprocess_data()
detector_con_modelo.evaluate_model()