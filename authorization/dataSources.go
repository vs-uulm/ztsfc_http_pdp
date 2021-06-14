package trustCalculation

/*
In this file the threshold values for the three provided services, the trust-increase for user-attributes, the
trust-increase for device attributes, user-information for registered users and device-information of managed devices
are stored
 */

type DataSources struct {

	// Trust-increase, when a DPI SF is used
	dpiTrustIncrease int

    // Trust-increase, when a Logger SF is used
    loggerTrustIncrease int

	// Maximum authentication attempts to get trust for the attribute authentication attempts
	maxAuthAttempts int

	// Map, where threshold values for the devices are stored
	thresholdValues map[string]map[string]int

	// Map, where the trust-increase of user attributes is provided, when these attributes are fulfilled
	trustIncreaseUserAttr map[string]int

	// Map, where the trust-increase of device attributes is provided, when these attributes are fulfilled
	trustIncreaseDeviceAttr map[string]int

	// Map, where the current status of each user is stored (= user database)
	//UserDatabase map[string]*User

	// Map, where the current status of managed devices is stored (= device database)
	deviceDatabase map[string]int

	// Map, where for a User the usual geographic area is stored
	mapUsergeoArea map[string]string

    // Map that represents the usual # of requests for a specific user per day
	usualRequests map[string]int
}

func NewDataSources() *DataSources {
	dataSources := DataSources{}
	dataSources.InitDataSources()
	return &dataSources
}


/*
In this method values are assigned to the specified attributes
 */
func (dataSources *DataSources) InitDataSources()  {
	dataSources.dpiTrustIncrease = 6
    dataSources.loggerTrustIncrease = 2

	dataSources.maxAuthAttempts = 3

	dataSources.thresholdValues = make(map[string]map[string]int)
    service1Actions := make(map[string]int)
    service1Actions["GET"] = 10
	dataSources.thresholdValues["service1.testbed.informatik.uni-ulm.de"] = service1Actions
	dataSources.thresholdValues["service2.testbed.informatik.uni-ulm.de"] = service1Actions

	dataSources.trustIncreaseUserAttr = make(map[string]int)
	dataSources.trustIncreaseUserAttr["UGA"] = 1	// Usual geographic area
	dataSources.trustIncreaseUserAttr["CUS"] = 2	// Commonly used services
	dataSources.trustIncreaseUserAttr["UAR"] = 2	// Usual amount of requests
	dataSources.trustIncreaseUserAttr["AA"] = 3	// Authentication attempts
	dataSources.trustIncreaseUserAttr["CRT"] = 2	// Authentication with a client-certificate
	dataSources.trustIncreaseUserAttr["PW"] = 1	// Authentication with a client-certificate and a password

	dataSources.trustIncreaseDeviceAttr = make(map[string]int)
	dataSources.trustIncreaseDeviceAttr["LPL"] = 3	// Latest patch level
	dataSources.trustIncreaseDeviceAttr["NAVS"] = 2	// No alerts of virus scanner
	dataSources.trustIncreaseDeviceAttr["RI"] = 1	// Device recently re-installed

	dataSources.deviceDatabase = make(map[string]int)

    dataSources.deviceDatabase["device1"] = 3
    dataSources.deviceDatabase["device2"] = 3
    dataSources.deviceDatabase["device3"] = 1
    dataSources.deviceDatabase["device4"] = 1
    dataSources.deviceDatabase["device5"] = 0


	// create managed devices in the device database
	//var device1 = make(map[string]bool)
	//dataSources.deviceDatabase["device1"] = device1
	//device1["LPL"] = true
	//device1["NAVS"] = true
	//device1["RI"] = true

	//var device2 = make(map[string]bool)
	//dataSources.deviceDatabase["device2"] = device2
	//device2["LPL"] = true
	//device2["NAVS"] = true
	//device2["RI"] = true

	//var device3 = make(map[string]bool)
	//dataSources.deviceDatabase["device3"] = device3
	//device3["LPL"] = true
	//device3["NAVS"] = true
	//device3["RI"] = true

	// create users in the user database
	//dataSources.UserDatabase = make(map[string]*User)
	//alex := NewUser("DE",[]string{"service1","service2","service3"},10000,0,0)
	//ceo := NewUser("DE",[]string{"service1","service2","service3"},10000,0,0)
	//man := NewUser("DE",[]string{"service1","service2","service3"},10000,0,0)
	//dev := NewUser("DE",[]string{"service1","service2","service3"},10000,0,0)
	//dataSources.UserDatabase["alex"] = alex
	//dataSources.UserDatabase["ceo"] = ceo
	//dataSources.UserDatabase["man"] = man
	//dataSources.UserDatabase["dev"] = dev

	// assign ip-addresses to geographic areas (exemplary values)
	dataSources.mapUsergeoArea = make(map[string]string)
	dataSources.mapUsergeoArea["bender"]="us"
	dataSources.mapUsergeoArea["fry"]="us"
	dataSources.mapUsergeoArea["zoidberg"]="de"
    dataSources.mapUsergeoArea["professor"]="fr"
    dataSources.mapUsergeoArea["hermes"]="us"

	// usual amount of requests per today for a user (exemplary values)
	dataSources.usualRequests = make(map[string]int)
	dataSources.usualRequests["bender"]=100
	dataSources.usualRequests["fry"]=100
	dataSources.usualRequests["zoidberg"]=100
	dataSources.usualRequests["professor"]=100
	dataSources.usualRequests["hermes"]=100

}
