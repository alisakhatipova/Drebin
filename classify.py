#!/usr/bin/python
import numpy as np
import matplotlib.pyplot as plt
import mlpy
import os
import json
import time
malw_dir = 'feature_vectors/fv_bad_train'
ben_dir = 'feature_vectors/fv_good_train'
test_b = 'feature_vectors/fv_good_test'
test_m = 'feature_vectors/fv_bad_test'

#interesting_api = open('all.txt').read().splitlines()
time1 = time.time()
features_malware = []
for f_file in os.listdir(malw_dir):
	f = open(malw_dir + '/' + f_file)
	cur_features = f.read()
	f.close()
	cur_features = list(cur_features)
	cur_features = map(lambda x: int(x), cur_features)
	if len(cur_features) != 26131:
                print('fatal error')
	features_malware.append(cur_features)

features_benign = []
for f_file in os.listdir(ben_dir):
	f = open(ben_dir + '/' + f_file)
	cur_features = f.read()
	f.close()
	cur_features = list(cur_features)
	cur_features = map(lambda x: int(x), cur_features)
	if len(cur_features) != 26131:
                print('fatal error')
	features_benign.append(cur_features)

features_test_m = []
for f_file in os.listdir(test_m):
	f = open(test_m + '/' + f_file)
	cur_features = f.read()
	f.close()
	cur_features = list(cur_features)
	cur_features = map(lambda x: int(x), cur_features)
	if len(cur_features) != 26131:
                print('fatal error')
	features_test_m.append(cur_features)

features_test_b = []
for f_file in os.listdir(test_b):
	f = open(test_b + '/' + f_file)
	cur_features = f.read()
	f.close()
	cur_features = list(cur_features)
	cur_features = map(lambda x: int(x), cur_features)
	if len(cur_features) != 26131:
                print('fatal error')
	features_test_b.append(cur_features)

x1 = np.array(features_malware)
y1 = -1* np.ones(len(features_malware), dtype=np.int)
x2 = np.array(features_benign)
y2 = np.ones(len(features_benign), dtype=np.int)
x = np.concatenate((x1, x2), axis=0) # concatenate the samples
y = np.concatenate((y1, y2))
'''
knn = mlpy.Knn(k=2)
knn.compute(x, y)
marks = knn.predict(np.array(features_test_m))
'''
mysvm = mlpy.Svm()
mysvm.compute(x, y)
marks = mysvm.predict(np.array(features_test_m))

count = 0
for mark in marks:
	if mark == 1:
		count += 1
print 'Wrongly classified', count, '/', len(features_test_m), count*100.0/len(features_test_m), 'malware samples'

#marks = knn.predict(np.array(features_test_b))
marks = mysvm.predict(np.array(features_test_b))
count = 0
for mark in marks:
	if mark == -1:
		count += 1
print 'Wrongly classified', count, '/', len(features_test_b), count*100.0/len(features_test_b), 'benign samples'
time2 = time.time()
print (time2 - time1)
