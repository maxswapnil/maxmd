#flask imports
from flask import Flask
import os
import pickle
import numpy as np
import pandas as pd
from sklearn import metrics
from joblib import dump, load
from sklearn.metrics import accuracy_score


#imports for model
import sys
import time
import os.path
import importlib

#initialize the flask app
app = Flask(__name__)
global RF

@app.route('/', methods = ['GET'])
def index():
    return '<h2> Send 28 Features for prediction </h2>'


@app.route('/<features>', methods = ['GET'])
def predict(features=None):
    output = {'Malicious': 'False'}
    
    PEFeature = features.split(',') 
    df2 =[(PEFeature[0],PEFeature[1],PEFeature[2],PEFeature[3],PEFeature[4],PEFeature[5],PEFeature[6],PEFeature[7],PEFeature[8],PEFeature[9],PEFeature[10],PEFeature[11],PEFeature[12],PEFeature[13],PEFeature[14],PEFeature[15],PEFeature[16],PEFeature[17],PEFeature[18],PEFeature[19],PEFeature[20],PEFeature[21],PEFeature[22],PEFeature[23],PEFeature[24],PEFeature[25],PEFeature[26],PEFeature[27])]

    details = pd.DataFrame(df2, columns =['Characteristics','MajorLinkerVersion','SizeOfCode','SizeOfInitializedData','AddressOfEntryPoint','MajorOperatingSystemVersion','MajorSubsystemVersion','Checksum','Subsystem','DllCharacteristics','SizeOfStackReserve','SectionsNb','SectionsMeanEntropy','SectionsMinEntropy','SectionsMaxEntropy','SectionsMeanRawsize','SectionsMinRawsize','SectionsMeanVirtualsize','SectionMaxVirtualsize','ImportsNbDLL','ResourcesMeanEntropy','ResourcesMinEntropy','ResourcesMaxEntropy','ResourcesMeanSize','ResourcesMinSize','ResourcesMaxSize','LoadConfigurationSize','VersionInformationSize'])

    labels = 0

    test_data = np.array(details)

    predictions = RF.predict_proba(test_data)

    for item in predictions:
        if (item[1] < 0.5):
            output = {'Malicious': 'True'}
    return output


if __name__ == '__main__':
    RF = load('tree.joblib')
    app.run()
