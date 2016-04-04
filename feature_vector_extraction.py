#!/usr/bin/python
# coding=utf-8
from __future__ import print_function
import sys
import hashlib
import os
import json
import time
sys.path.append('../../androguard')
from androguard.core.bytecode import *

from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *
import androlyze as anz

mode = "libs"
'''
if mode == "no_libs":
	interesting_api = interesting_api_no_libs
'''

api_json = 'api.json'


known_libs = [
	# Big companies and SDKs
	'android',
	'com.android',
	'com.google',
	'com.facebook',
	'com.adobe',
	'org.apache',
	'com.amazon',
	'com.amazonaws',
	'com.dropbox',
	'com.paypal',
	'twitter4j',
	'mono',
	'gnu',

	# Other stuff
	'org.kobjects',
	'com.squareup',
	'com.appbrain',
	'org.kxml2',
	'org.slf4j',
	'org.jsoup',
	'org.ksoap2',
	'org.xmlpull',
	'com.nineoldandroids',
	'com.actionbarsherlock',
	'com.viewpagerindicator',
	'com.nostra13.universalimageloader',
	'com.appyet', # App creator: appyet.com
	'com.fasterxml.jackson', # A suite of data-processing tools for Java: github.com/FasterXML/jackson
	'org.anddev.andengine', 'org.andengine', # Free Android 2D OpenGL Game Engine: andengine.org
	'uk.co.senab.actionbarpulltorefresh', # A pull-to-refresh lib: github.com/chrisbanes/ActionBar-PullToRefresh
	'fr.castorflex.android.smoothprogressbar', # A progressbar lib: github.com/castorflex/SmoothProgressBar
	'org.codehaus', # org.codehaus.jackson, org.codehaus.mojo, etc.
	'org.acra', # Application crash reports lib
	'com.appmk', # SDK for building simple android apps without programming (books, magazines)
	'com.j256.ormlite', # ORM library
	'nl.siegmann.epublib', #java library for managing epub files
	'pl.polidea', #Android library which simplifies displaying, caching and managing a lifecycle of images fetched from the web
	'uk.co.senab', #library for pull-to-refresh interaction
	'com.onbarcode', #library for QRcode
	'com.googlecode.apdfviewer', #library for viewing pdf
	'com.badlogic.gdx', #Java game development framework
	'com.crashlytics', #integrations for popular third-party services
	'com.mobeta.android.dslv', #extension of the Android ListView that enables drag-and-drop reordering of list items
	'com.andromo', #simplifies app creation
	'oauth.signpost', #for signing http messages
	'com.loopj.android.http', #An asynchronous callback-based Http client for Android built on top of Apache’s HttpClient libraries.
	'com.handmark.pulltorefresh.library', #aims to provide a reusable Pull to Refresh widget for Android
	'com.bugsense.trace', #Remotely log unhandled exceptions in Android applications
	'org.cocos2dx.lib', #project demonstrating a method of setting a global opacity on a particle system
	'com.esotericsoftware', #for creating games
	'javax.inject', #package specifies a means for obtaining objects in such a way as to maximize reusability, testability and maintainability compared to traditional approaches 
	'com.parse', #framework for creating apps
	'org.joda.time', #date and time library for Java
	'com.androidquery', #library for doing asynchronous tasks and manipulating UI elements in Android
	'crittercism.android', #Monitor, prioritize, troubleshoot, and trend your mobile app performance
	'biz.source_code.base64Coder', #A Base64 encoder/decoder in Java
	'v2.com.playhaven', #mobile game LTV-maximization platform
	'xmlwise', #Xmlwise aims to make reading and writing of simple xml-files painless
	'org.springframework', #Spring Framework provides a comprehensive programming and configuration model for modern Java-based enterprise applications
	'org.scribe', #The best OAuth library out there
	'org.opencv', #OpenCV was designed for computational efficiency and with a strong focus on real-time applications
	'org.dom4j',
	'net.lingala.zip4j', #An open source java library to handle zip files
	'jp.basicinc.gamefeat', #Looks like a framework for games, Chineese
	'gnu.kawa', #Kawa is a general-purpose programming language that runs on the Java platform
	'com.sun.mail', #JavaMail API
	'com.playhaven', #Mobile Gaming Monetization Platform
	'com.commonsware.cwac', #open source libraries to help solve various tactical problems with Android development
	'com.comscore', #Analytics
	'com.koushikdutta', # low level network protocol library
	'com.mapbar', #Maps
	'greendroid', #GreenDroid is a development library for the Android platform. It is intended to make UI developments easier and consistent through your applications.
	'javax', #Java API
	'org.intellij', # Intellij

	# Ad networks
	'com.millennialmedia',
	'com.inmobi',
	'com.revmob',
	'com.mopub',
	'com.admob',
	'com.flurry',
	'com.adsdk',
	'com.Leadbolt',
	'com.adwhirl', # Displays ads from different ad networks
	'com.airpush',
	'com.chartboost', #In fact, SDK for displaying appropriate network
	'com.pollfish',
	'com.getjar', #offerwall for Android,
	'com.jb.gosms',
	'com.sponsorpay',
	'net.nend.android',
	'com.mobclix.android',
	'com.tapjoy',
	'com.adfonic.android',
	'com.applovin',
	'com.adcenix',
	'com.ad_stir',
	#Ad networks found in drebin database (still looking good)
	'com.madhouse.android.ads',
	'com.waps',
	'net.youmi.android',
	'com.vpon.adon',
	'cn.domob.android.ads',
	'com.wooboo.adlib_android',
	'com.wiyun.ad',

	#Some unknown libs
	'com.jeremyfeinstein.slidingmenu.lib',
	'com.slidingmenu.lib',
	'it.sephiroth.android.library',
	'com.gtp.nextlauncher.library',
	'jp.co.nobot.libAdMaker',
	'ch.boye.httpclientandroidlib',
	'magmamobile.lib',
	'com.magmamobile'
]

#Loading framework methods
f = open(api_json, 'r')
framework_api = json.loads(f.read())
f.close()

f = open('restricted_api')
susp_api = f.read().splitlines()
f.close()

f = open('suspicious_api')
dang_api = f.read().splitlines()
f.close()

def get_real_permissions(d):
        try:
                dx = uVMAnalysis(d)
        except:
                print ('Failed to uVMAnalysis structure')
		return None
        try:
                lst = dx.get_permissions([])
                lst = lst.keys()
                return lst
        except:
                print ('Failed to get real perms')
		return None
		
def get_used_addresses(d):
        result= []
        try:
                lst = d.get_strings()
        except:
                print ('Failed to get strings')
		return None
        for line in lst:
                if 'http://' in line or 'https://' in line or '.net' in line or '.org' in line or '.ru' in line or '.com' in line:
                        result.append(line)
        return result
	
def get_used_hw_features(a):
        result= []
        try:
                manif = a.get_android_manifest_xml()
        except:
                print ('Failed to get Android Manifest')
		return None
	try:
                lst = manif.getElementsByTagName("uses-feature")
                for item in lst:
                        try:
                                attrlist = item.attributes['android:name']
                        except:
                                continue
                        result.append(attrlist.value)
                return result
        except:
                print('Error while extracting hardware features')
                return None

def get_used_intents(a):
        result= []
        try:
                manif = a.get_android_manifest_xml()
        except:
                print ('Failed to get Android Manifest')
		return None
	try:
                lst = manif.getElementsByTagName("intent-filter")
                for sublst in lst:
                        for item in sublst.childNodes:      
                                try:
                                        attrlist = item.attributes['android:name']
                                except:
                                        continue
                                result.append(attrlist.value)
                return result
        except:
                print('Error while extracting intents')
                return None
        
def get_used_api(d):
	def compute_self_methods(d):
		self_methods = []
		for cl in d.get_classes():
			package_method = False
			for package in known_libs:
				package_name = "L" + package + "/"
				package_name = package_name.replace(".", "/")
				if package_name in cl.get_name():
					package_method = True
					break
			if package_method:
				continue
			if not cl.get_name() in framework_api:
				self_methods.extend(cl.get_methods())
		return self_methods


	try:
		used_api = []
		if mode == "no_libs":
			method_list = compute_self_methods(d)
		else:
			method_list = d.get_methods()
		for method in method_list:
			if method.get_code() == None:
				continue

			cur_method = method.get_class_name() + "->" + method.get_name() + method.get_descriptor()
			for ins in method.get_instructions():
				if "invoke" in ins.get_name():
					call_method = ""
					matchObj = re.match( r'.*, ([^,]*)', ins.get_output(), re.M|re.I)
					if (matchObj):
						call_method = matchObj.group(1)
						if call_method[:1] == '[':
							call_method = call_method[1:]
						if call_method != "":
							call_method_class = call_method.split('->')[0]
							call_method_name = call_method.split('->')[1].split('(')[0]
							if call_method_class in framework_api \
								and call_method_name in framework_api[call_method_class] and \
								not call_method_class + call_method_name in used_api:
								used_api.append((call_method_class  + call_method_name)[1:])

		return used_api
	except:
		print ('Failed to count api')
		return None
'''
if len(sys.argv) < 2:
	print ('APK argument required')
	sys.exit()
'''
#apk_name = sys.argv[1]

path_apps = ['apks/bad_apps_train', 'apks/good_apps_train', 'apks/bad_apps_test', 'apks/good_apps_test']
path_fv = [ 'feature_vectors/fv_bad_train', 'feature_vectors/fv_good_train', 'feature_vectors/fv_bad_test', 'feature_vectors/fv_good_test']
path_full_list = 'feature_vectors'
interesting = []
time1 = time.time()

#directories 0 and 1 - with apps for train, after extraction of features we need to add them to the common list (interesting []). 
#After that dump app features in mere text format to the file (can't work with them until full features list is done)
#When we get to i = 2 feature list is complete and we can compute feature vectors in format '00101...0101' consisting of N elements
#(where N is length of full features list) right away. After this is finished we should get back to train apps and transform their files to files
#with feature vectors of binary format. It all is done to reduce the size of final feature set (don't have much memory in my computer :) ), executing time
#(spending less time on writing in file all features, but only 0 and 1) and size of memory consumed during the script execution.

for i in range(4):
	list_p = os.listdir(path_apps[i])
	list_p = map(lambda x: path_apps[i] + '/' + x,list_p)
	for apk_name in list_p:
		apk_hash = hashlib.sha256(open(apk_name, 'r').read()).hexdigest()
		save_directory = path_fv[i]
		
		try:
                        #Androguard structures
                        a = APK(apk_name)
                        d = dvm.DalvikVMFormat( a.get_dex() )
                        api = get_used_api(d)
                        intents = get_used_intents(a)
                        hw_features = get_used_hw_features(a)
                        permissions = a.get_permissions()
                        receivers = a.get_receivers()
                        services = a.get_services()
                        providers = a.get_providers()
                        activities = a.get_activities()
                        real_permissions = get_real_permissions(d)
                        #addresses = get_used_addresses(d)
                        
                        app_features = []

                        for item in api:
                                if item in susp_api:
                                        carry = 'api_call::' + item
                                        if not carry in app_features:
                                                app_features.append(carry)
                                        if i<2 and not carry in interesting:
                                                interesting.append(carry)
                                if item in dang_api:
                                        carry = 'call::' + item
                                        if not carry in app_features:
                                                app_features.append(carry)
                                        if  i<2 and not carry in interesting:
                                                interesting.append(carry)    
                        for item in intents:
                                carry = 'intent::' + item
                                if not carry in app_features:
                                        app_features.append(carry)
                                if i<2 and  not carry in interesting:
                                        interesting.append(carry)
                        for item in hw_features:
                                carry = 'feature::' + item
                                if not carry in app_features:
                                        app_features.append(carry)
                                if  i<2 and not carry in interesting:
                                        interesting.append(carry)
                        for item in permissions:
                                carry = 'permission::' + item
                                if not carry in app_features:
                                        app_features.append(carry)
                                if i<2 and  not carry in interesting:
                                        interesting.append(carry)
                        for item in receivers:
                                carry = 'service_receiver::' + item
                                if not carry in app_features:
                                        app_features.append(carry)
                                if i<2 and  not carry in interesting:
                                        interesting.append(carry)
                        for item in services:
                                carry = 'service::' + item
                                if not carry in app_features:
                                        app_features.append(carry)
                                if  i<2 and not carry in interesting:
                                        interesting.append(carry)
                        for item in providers:
                                carry = 'provider::' + item
                                if not carry in app_features:
                                        app_features.append(carry)
                                if  i<2 and not carry in interesting:
                                        interesting.append(carry)
                        for item in activities:
                                carry = 'activity::' + item
                                if not carry in app_features:
                                        app_features.append(carry)
                                if  i<2 and not carry in interesting:
                                        interesting.append(carry)
                        for item in real_permissions:
                                carry = 'real_permission::' + item
                                if not carry in app_features:
                                        app_features.append(carry)
                                if  i<2 and not carry in interesting:
                                        interesting.append(carry)
                        '''
                        for item in addresses:
                                carry = 'address::' + item
                                if not carry in app_features:
                                        app_features.append(carry)
                                if  i<2 and not carry in interesting:
                                        interesting.append(carry)
                        '''        
                except:
                        print('smth wrong')
                        continue
		if i < 2:
			f = open(save_directory + "/" + apk_hash, 'w')
		        for item in app_features:
		                f.write(item)
		                f.write('\n')
		        f.close()
		else:
			f = open(save_directory + "/" + apk_hash, 'w')
		        str_f = ''
		        for item in interesting:
		                if item in app_features:
		                        str_f +='1'
		                else:
		                        str_f +='0'
		        f.write(str_f)
		        f.close()

#dump full feature list to the file just in case we need it                
f = open(path_full_list + "/" + 'full_list', 'w')
for item in interesting:
        f.write(item)
        f.write('\n')
f.close()        

#for train set our feature list is still in text format - now having full feature list 
#we can get a feature vector for each app consisting of 0 and 1
for i in range(2):
	list_p = os.listdir(path_fv[i])
	list_p = map(lambda x: path_fv[i] + '/' + x,list_p)
        for f_file in list_p:
                f = open(f_file)
                app_features = f.read().splitlines()
                f.close()
                features = {}
                str_f = ''
                for item in interesting:
                        if item in app_features:
                                str_f +='1'
                        else:
                                str_f +='0'
                f = open(f_file, 'w')
                f.write(str_f)
                f.close()	
time2 = time.time() - time1
print(time2)
