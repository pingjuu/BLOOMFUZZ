import re, sys
from OuiLookup import OuiLookup
import bluetooth



def bluetooth_class_of_device(device_class):
    # https://github.com/mikeryan/btclassify.git

    class_string = device_class

    m = re.match('(0x)?([0-9A-Fa-f]{6})', class_string)
    if m is None:
        #print("Invalid class, skipping (%s)" % class_string)
        return { "major": "None", "minor": "None", "service": "None"}

    hex_string = m.group(2)

    # "class" is a reserved word in Python, so CoD is class
    CoD = int(hex_string, 16)
   
    # Major Device Classes
    classes = ["Miscellaneous", "Computer", "Phone", "LAN/Network Access Point",
               "Audio/Video", "Peripheral", "Imaging", "Wearable", "Toy",
               "Health"]
    major_number = (CoD >> 8) & 0x1f
    if major_number < len(classes):
        major = classes[major_number]
    elif major_number == 31:
        major = "Uncategorized"
    else:
        major = "Reserved"

    # Minor - varies depending on major
    minor_number = (CoD >> 2) & 0x3f
    minor = None

    # computer
    if major_number == 1:
        classes = [
            "Uncategorized", "Desktop workstation", "Server-class computer",
            "Laptop", "Handheld PC/PDA (clamshell)", "Palm-size PC/PDA",
            "Wearable computer (watch size)", "Tablet"]
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = "reserved"

    # phone
    elif major_number == 2:
        classes = [
            "Uncategorized", "Cellular", "Cordless", "Smartphone",
            "Wired modem or voice gateway", "Common ISDN access"]
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = "reserved"

    # network access point
    elif major_number == 3:
        minor_number >> 3
        classes = [
            "Fully available", "1% to 17% Utilized", "17% to 33% Utilized",
            "33% to 50% Utilized", "50% to 67% Utilized",
            "67% to 83% Utilized", "83% to 99% Utilized",
            "No service available"]
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = "reserved"

    # audio/video
    elif major_number == 4:
        classes = [
            "Uncategorized", "Wearable Headset Device", "Hands-free Device",
            "(Reserved)", "Microphone", "Loudspeaker", "Headphones",
            "Portable Audio", "Car audio", "Set-top box", "HiFi Audio Device",
            "VCR", "Video Camera", "Camcorder", "Video Monitor",
            "Video Display and Loudspeaker", "Video Conferencing",
            "(Reserved)", "Gaming/Toy"]
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = "reserved"

    # peripheral, this one's gross
    elif major_number == 5:
        feel_number = minor_number >> 4
        classes = [
            "Not Keyboard / Not Pointing Device", "Keyboard",
            "Pointing device", "Combo keyboard/pointing device"]
        feel = classes[feel_number]

        classes = [
            "Uncategorized", "Joystick", "Gamepad", "Remote control",
            "Sensing device", "Digitizer tablet", "Card Reader", "Digital Pen",
            "Handheld scanner for bar-codes, RFID, etc.",
            "Handheld gestural input device" ]
        if minor_number < len(classes):
            minor_low = classes[minor_number]
        else:
            minor_low = "reserved"
        
        minor = '%s, %s' % (feel, minor_low)

    # imaging
    elif major_number == 6:
        minors = []
        if minor_number & (1 << 2):
            minors.append("Display")
        if minor_number & (1 << 3):
            minors.append("Camera")
        if minor_number & (1 << 4):
            minors.append("Scanner")
        if minor_number & (1 << 5):
            minors.append("Printer")
        if len(minors > 0):
            minors = ', '.join(minors)

    # wearable
    elif major_number == 7:
        classes = ["Wristwatch", "Pager", "Jacket", "Helmet", "Glasses"]
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = "reserved"

    # toy
    elif major_number == 8:
        classes = ["Robot", "Vehicle", "Doll / Action figure", "Controller",
                   "Game"]
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = "reserved"

    # health
    elif major_number == 9:
        classes = [
            "Undefined", "Blood Pressure Monitor", "Thermometer",
            "Weighing Scale", "Glucose Meter", "Pulse Oximeter",
            "Heart/Pulse Rate Monitor", "Health Data Display", "Step Counter",
            "Body Composition Analyzer", "Peak Flow Monitor",
            "Medication Monitor", "Knee Prosthesis", "Ankle Prosthesis",
            "Generic Health Manager", "Personal Mobility Device"]
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = "reserved"

    # Major Service Class (can by multiple)
    services = []
    if CoD & (1 << 23):
        services.append("Information")
    if CoD & (1 << 22):
        services.append("Telephony")
    if CoD & (1 << 21):
        services.append("Audio")
    if CoD & (1 << 20):
        services.append("Object Transfer")
    if CoD & (1 << 19):
        services.append("Capturing")
    if CoD & (1 << 18):
        services.append("Rendering")
    if CoD & (1 << 17):
        services.append("Networking")
    if CoD & (1 << 16):
        services.append("Positioning")
    if CoD & (1 << 15):
        services.append("(reserved)")
    if CoD & (1 << 14):
        services.append("(reserved)")
    if CoD & (1 << 13):
        services.append("Limited Discoverable Mode")

    output = {"major" : major, "minor" : minor, "service" : services}

    return output 

def bluetooth_classic_scan(test_info):
    """
    This scan finds ONLY Bluetooth Classic (non-BLE) devices
    """
    print('Performing classic bluetooth inquiry scan...')

    while(True):
        # Scan for nearby devices in regular bluetooth mode
        nearby_devices = bluetooth.discover_devices(duration=3, flush_cache=True, lookup_names=True, lookup_class=True)
        print("nearby devices : {}".format(len(nearby_devices)))
        i = 0
        print("\n\tTarget Bluetooth Device List")
        print("\t[No.]\t[BT address]\t\t[Device name]\t\t[Device Class]\t\t[OUI]")
        for addr, name, device_class in nearby_devices:
            device_class = bluetooth_class_of_device(hex(device_class))
            oui = OuiLookup().query(addr)
            print("\t%02d.\t%s\t%s\t\t%s(%s)\t%s" % (i, addr, name, device_class["major"], device_class["minor"], list(oui[0].values())[0]))                
            i += 1
        if len(nearby_devices) == 0:
            print("[-] No bluetooth device found. Did you connect an adapter?\n")
            sys.exit()
        elif len(nearby_devices) != 0:
            print("\tFound %d devices" % len(nearby_devices))
            break
        else :
            sys.exit()
    
    while(True):
        user_input = int(input("\nChoose Device : "))
        if user_input < len(nearby_devices) and user_input > -1:
            idx = user_input
            break
        else:
            print("[-] Out of range.")
    
    addr_chosen = nearby_devices[idx][0]
    test_info["bdaddr"] = str(nearby_devices[idx][0])
    oui = OuiLookup().query(addr_chosen)
    test_info["OUI"] = list(oui[0].values())[0]
    test_info["name"] = str(nearby_devices[idx][1])
    test_info["Class of Device Value"] = str(nearby_devices[idx][2])
    test_info["Class of Device"] = bluetooth_class_of_device(hex(nearby_devices[idx][2]))

    return test_info, addr_chosen
