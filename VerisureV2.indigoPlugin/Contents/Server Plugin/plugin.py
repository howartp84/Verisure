#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################

import indigo
import re
import os
import sys
import time
from datetime import datetime, timedelta
import logging
import verisure
import json
import traceback
#logging.getLogger("verisure").setLevel(logging.WARNING)
#logging.getLogger("requests").setLevel(logging.WARNING)
#logging.getLogger("urllib3").setLevel(logging.WARNING)

# Note the "indigo" module is automatically imported and made available inside
# our global name space by the host process.

################################################################################
class Plugin(indigo.PluginBase):
	########################################
	def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
		super(Plugin, self).__init__(pluginId, pluginDisplayName, pluginVersion, pluginPrefs)
		self.debug = pluginPrefs.get("showDebugInfo", False)
		self.debug2 = pluginPrefs.get("showDebugInfo2", False)

		self.rateLimit = pluginPrefs.get("updateRate", 30)
		self.loggedIn = False
		self.gettingData = False

		self.lockIDs = list()
		self.alarmIDs = list()
		self.plugIDs = list()

		self.lidFromDev = dict()
		self.alarmidFromDev = dict()
		self.pidFromDev = dict()
		self.devFromLid = dict()
		self.devFromAlarmid = dict()
		self.devFromPid = dict()


	########################################
	def startup(self):
		self.debugLog(u"startup called")
		self.debugLog(u"rateLimit is %s" % self.rateLimit)
		if "verisureUsername" not in self.pluginPrefs or "verisurePassword" not in self.pluginPrefs:
			self.errorLog(u"Please enter Username and Password in Plugin Config")
		else:
			self.doLogin()


	def shutdown(self):
		self.debugLog(u"shutdown called")
		if self.loggedIn:
			self.doLogout()

	def closedPrefsConfigUi(self, valuesDict, userCancelled):
		self.debugLog(u"Plugin config dialog window closed.")
		if not userCancelled:
			self.debug = valuesDict.get("showDebugInfo", False)
			self.debug2 = valuesDict.get("showDebugInfo2", False)
			if self.debug:
				indigo.server.log("Debug logging enabled")
			else:
				indigo.server.log("Debug logging disabled")
			if self.debug2:
				indigo.server.log("Debug super logging enabled")
			else:
				indigo.server.log("Debug super logging disabled")
			self.rateLimit = int(valuesDict.get("updateRate", 30))
			self.debugLog(u"rateLimit is %s" % self.rateLimit)
			self.doLogin(True) #Logout first
		return

	def deviceStartComm(self, dev):
		dev.stateListOrDisplayStateIdChanged()
		if (dev.deviceTypeId == "verisureDoorLockDeviceType"):
			devID = dev.id																							#devID is the Indigo ID of my dummy device
			lockID = dev.ownerProps['deviceLabel']											#lockID is the deviceLabel of the Verisure lock

			self.lidFromDev[int(devID)] = str(lockID)
			self.devFromLid[str(lockID)] = int(devID)

			self.lockIDs.append(lockID)

			dev.updateStateOnServer("deviceLabel",lockID)

		elif (dev.deviceTypeId == "verisureAlarmDeviceType"):
			devID = dev.id																							#devID is the Indigo ID of my dummy device
			alarmID = dev.ownerProps['alarmID']													#alarmID is the locationID of the Verisure installation
			dev.updateStateOnServer("locationID",alarmID)

			self.alarmidFromDev[int(devID)] = str(alarmID)
			self.devFromAlarmid[str(alarmID)] = int(devID)

			self.alarmIDs.append(alarmID)

		elif (dev.deviceTypeId == "verisureSmartPlugDeviceType"):
			devID = dev.id																							#devID is the Indigo ID of my dummy device
			plugID = dev.ownerProps['deviceLabel']											#plugID is the deviceLabel of the Verisure plug

			self.pidFromDev[int(devID)] = str(plugID)
			self.devFromPid[str(plugID)] = int(devID)

			self.plugIDs.append(plugID)

			dev.updateStateOnServer("deviceLabel",plugID)


	def deviceStopComm(self, dev):
		if (dev.deviceTypeId == "verisureDoorLockDeviceType"):
			devID = dev.id
			lockID = dev.ownerProps['deviceLabel']

			self.lidFromDev.pop(int(devID),None)
			self.devFromLid.pop(str(lockID),None)

			self.lockIDs.remove(lockID)

		elif (dev.deviceTypeId == "verisureAlarmDeviceType"):
			devID = dev.id
			alarmID = dev.ownerProps['alarmID']

			self.alarmidFromDev.pop(int(devID),None)
			self.devFromAlarmid.pop(str(alarmID),None)

			self.alarmIDs.remove(alarmID)

		elif (dev.deviceTypeId == "verisureSmartPlugDeviceType"):
			devID = dev.id
			plugID = dev.ownerProps['deviceLabel']

			self.pidFromDev.pop(int(devID),None)
			self.devFromPid.pop(str(plugID),None)

			self.plugIDs.remove(plugID)


	def doLogin(self,logout=False):
		if logout:
			self.debugLog(u"Logging out first")
			self.doLogout()
		if not self.loggedIn:
			cookiePath = str(indigo.server.getInstallFolderPath()) + "/Plugins/VerisureV2.indigoPlugin/Contents/Server Plugin/verisure/.verisure-cookie"
			self.debugLog(u"Creating session")
			self.session = verisure.Session(self.pluginPrefs["verisureUsername"], self.pluginPrefs["verisurePassword"],cookiePath)
			self.debugLog(u"Logging in")
			self.session.login()
			if (hasattr(self.session,"_vid") and self.session._vid != None):
				self.debugLog("Logged in successfully")
				self.loggedIn = True
			else:
				self.debugLog("Logging in failed")
				self.overview = None
				self.loggedIn = False

		if self.loggedIn:
			self.refreshData()

	def doLogout(self):
		self.loggedIn = False
		try:
			self.debugLog(u"Session exists - logging out")
			self.session.logout()
			delattr(self,"session")
		except:
			pass

	def refreshData(self):
		if not self.loggedIn:
			self.doLogin()
		else: 					#doLogin() calls refreshData if it succeeds, so need else or we'll get stuck in loop
			#self.overview = self.session.get_overview()

			self.debugLog(u"Checking status for all Verisure Devices")
			self.overview = self.session.get_overview()

			doorLocks = self.overview['doorLockStatusList']
			for doorLock in doorLocks:
				lockID = doorLock["deviceLabel"]
				if lockID in self.lockIDs:
					dev = indigo.devices[int(self.devFromLid[str(lockID)])]
					dev.updateStateOnServer("lastSynchronized", value=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
					for key in doorLock.keys():
						try:
							dev.updateStateOnServer(key,doorLock[key])
							if (key == "area") and ("new device" in dev.name):
								dev.name = u"Lock: %s" % doorLock[key]
								dev.replaceOnServer()
						except:
							pass
					#Setting correct icon
					if dev.states['currentLockState'] == u"LOCKED":
						dev.updateStateImageOnServer(indigo.kStateImageSel.Auto)
						dev.updateStateOnServer('onOffState', True)
					elif dev.states['currentLockState'] == u"UNLOCKED":
						dev.updateStateImageOnServer(indigo.kStateImageSel.Auto)
						dev.updateStateOnServer('onOffState', False)
					elif dev.states['currentLockState'] == u"PENDING":
						dev.updateStateImageOnServer(indigo.kStateImageSel.TimerOn)
					else:
						dev.updateStateImageOnServer(indigo.kStateImageSel.Error)
					lConfig = self.session.get_lock_config(lockID)
					dev.updateStateOnServer('autoLockEnabled', lConfig["autoLockEnabled"])

			#userTracking = self.overview['userTracking'] #Removed by Verisure October 2020 :(
			#locations = userTracking['locations']


			#for location in locations:
			armState = self.overview['armState']
			alarmID = "myAlarm"
			if alarmID in self.alarmIDs:
				dev = indigo.devices[int(self.devFromAlarmid[str(alarmID)])]
				dev.updateStateOnServer("lastSynchronized", value=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
				#dev.updateStateOnServer("location",location["locationName"])
				if ("new device" in dev.name):
					dev.name = u"Verisure Alarm"
					dev.replaceOnServer()
				for key in armState.keys():
					try:
						#self.debugLog("%s > %s" % (key,armState[key]))
						dev.updateStateOnServer(key,armState[key])
					except:
						pass
				if dev.states['statusType'] == "ARMED_AWAY":
					dev.updateStateImageOnServer(indigo.kStateImageSel.Locked)
				elif dev.states['statusType'] == "ARMED_HOME":
					dev.updateStateImageOnServer(indigo.kStateImageSel.Locked)
				elif dev.states['statusType'] == "DISARMED":
					dev.updateStateImageOnServer(indigo.kStateImageSel.Unlocked)

			smartPlugs = self.overview['smartPlugs']
			for smartPlug in smartPlugs:
				plugID = smartPlug["deviceLabel"]
				if plugID in self.plugIDs:
					dev = indigo.devices[int(self.devFromPid[str(plugID)])]
					dev.updateStateOnServer("lastSynchronized", value=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
					for key in smartPlug.keys():
						try:
							dev.updateStateOnServer(key,smartPlug[key])
							if (key == "area") and ("new device" in dev.name):
								dev.name = u"Plug: %s" % smartPlug[key]
								dev.replaceOnServer()
						except:
							pass
					#Setting correct icon
					if dev.states["icon"] == "LIGHT":
						if dev.states["currentState"]:
							dev.updateStateImageOnServer(indigo.kStateImageSel.LightSensorOn)
						else:
							dev.updateStateImageOnServer(indigo.kStateImageSel.LightSensor)
					if dev.states['currentState'] == u"ON":
						dev.updateStateOnServer('onOffState', True)
					elif dev.states['currentState'] == u"OFF":
						dev.updateStateOnServer('onOffState', False)

	def getVerisureDeviceList(self, filter="All", typeId=0, valuesDict=None, targetId=0):
		self.refreshData()
		deviceList = []

		if(filter == "lock"):
			doorLocks = self.overview['doorLockStatusList']

			for doorLock in doorLocks:
				deviceList = deviceList + [(doorLock["deviceLabel"], doorLock["area"])]
		elif(filter == "alarm"):
			#userTracking = self.overview['userTracking']
			#locations = userTracking['locations']

			#for location in locations:
			deviceList = deviceList + [("myAlarm", "My Alarm")]

		elif(filter == "plug"):
			smartPlugs = self.overview['smartPlugs']

			for smartPlug in smartPlugs:
				deviceList = deviceList + [(smartPlug["deviceLabel"], smartPlug["area"])]

		return sorted(deviceList)

	def updateLockState(self, pluginAction, dev):
		cmd = pluginAction.props['new_status']
		self.session.set_lock_state(dev.ownerProps['userPin'],dev.ownerProps['deviceLabel'],cmd)
		dev.updateStateImageOnServer(indigo.kStateImageSel.TimerOn)
		self.sleep(5)
		self.refreshData()

	def updateLockConfig(self, pluginAction, dev):
		state = pluginAction.props['auto_lock_enabled']
		self.session.set_lock_config(dev.ownerProps['deviceLabel'],None,None,state)
		dev.updateStateOnServer('autoLockEnabled', state)
		self.sleep(5)
		self.refreshData()

	def UpdateAlarmStatus(self, pluginAction, dev):
		cmd = pluginAction.props['new_status']
		self.session.set_arm_state(dev.ownerProps['userPin'],dev.ownerProps['deviceLabel'],cmd)
		self.sleep(5)
		self.refreshData()

	def dumpOutput(self):
		if not self.loggedIn:
			self.doLogin()
		else:
			self.debugLog(self.session.get_overview())

	def debugLog2(self,msg):
		if self.debug2:
			self.debugLog(msg)

	########################################
	# If runConcurrentThread() is defined, then a new thread is automatically created
	# and runConcurrentThread() is called in that thread after startup() has been called.
	#
	# runConcurrentThread() should loop forever and only return after self.stopThread
	# becomes True. If this function returns prematurely then the plugin host process
	# will log an error and attempt to call runConcurrentThread() again after several seconds.
	def runConcurrentThread(self):
		try:
			while True:
				if self.gettingData: #We shouldn't be; this means we've crashed out
					self.debugLog2("rCT Crashed: 324")
					self.doLogin(True) #Logout and back in again

				if self.loggedIn:
					self.debugLog2("rCT refreshing")
					self.gettingData = True
					self.refreshData()
					self.gettingData = False

				self.debugLog2("rCT Sleeping %s" % str(self.rateLimit))
				self.sleep(int(self.rateLimit))
		except self.StopThread:
			self.debugLog("StopThread")
			pass	# Optionally catch the StopThread exception and do any needed cleanup.




	########################################
	# Action Control callback
	######################
	def actionControlDevice(self, action, dev):
		if (dev.deviceTypeId == "verisureDoorLockDeviceType"):
			if action.deviceAction == indigo.kDeviceAction.Lock or action.deviceAction == indigo.kDeviceAction.Unlock:
				if action.deviceAction == indigo.kDeviceAction.Unlock:
					if dev.states['currentLockState'] == u"LOCKED":
						indigo.server.log(u"sent \"%s\" %s" % (dev.name, "Unlock request"))
						cmd = 'unlock'
					else:
						indigo.server.log(u"sent \"%s\" %s" % (dev.name, "Already unlocked"))
						return #Already unlocked
				else:
					if dev.states['currentLockState'] == u"UNLOCKED":
						indigo.server.log(u"sent \"%s\" %s" % (dev.name, "Lock request"))
						cmd = 'lock'
					else:
						indigo.server.log(u"sent \"%s\" %s" % (dev.name, "Already locked"))
						return #Already locked
				self.session.set_lock_state(dev.ownerProps['userPin'],dev.ownerProps['deviceLabel'],cmd)
				dev.updateStateImageOnServer(indigo.kStateImageSel.TimerOn)
				self.sleep(5)
				self.refreshData()


	########################################
	# General Action callback
	######################
	def actionControlGeneral(self, action, dev):
		###### BEEP ######
		if action.deviceAction == indigo.kDeviceGeneralAction.Beep:
			# Beep the hardware module (dev) here:
			# ** IMPLEMENT ME **
			indigo.server.log(u"sent \"%s\" %s" % (dev.name, "beep request"))

		###### STATUS REQUEST ######
		elif action.deviceAction == indigo.kDeviceGeneralAction.RequestStatus:
			# Query hardware module (dev) for its current status here:
			# ** IMPLEMENT ME **
			indigo.server.log(u"sent \"%s\" %s" % (dev.name, "status request"))
			self.refreshData()

