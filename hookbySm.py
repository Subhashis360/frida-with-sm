import subprocess
import frida
import time
import sys

def on_message(message, payload):
    if message['type'] == 'send':
        print(f"Encountered: {message['payload']}")


def list_apps(device_id):
    try:
        adb_command = f"adb -s {device_id} shell pm list packages -f"
        result = subprocess.run(adb_command.split(), capture_output=True, text=True)
        app_list = result.stdout.strip().split('\n')
        packages = [line.split(':')[-1].split('=')[-1] for line in app_list]
        print("Installed Packages:")
        for idx, package in enumerate(packages):
            print(f"{idx}: {package}")
        return packages
    except Exception as e:
        print(f"Error: {e}")
        return []

def select_package(apps):
    try:
        selection = int(input("Enter the number corresponding to the package to hook: "))
        if selection < 0 or selection >= len(apps):
            print("Invalid selection.")
            return None
        return apps[selection]
    except ValueError:
        print("Invalid input. Enter a number.")
        return None



def start_frida_script(app_package, js_file):
    try:
        device = frida.get_usb_device(1)

        pid = device.spawn([app_package])
        device.resume(pid)
        time.sleep(1)
        process = device.attach(pid)
        with open(js_file, 'r') as file:
            script_code = file.read()
        script = process.create_script(script_code)
        script.on('message', on_message)
        script.load()
        sys.stdin.read()
            
            
    except frida.ServerNotRunningError:
        print("Frida server not running on the device. Please start Frida server.")
    except frida.TransportError:
        print("Error connecting to the device. Ensure Frida server is running and accessible.")
    except KeyboardInterrupt:
        print("Script stopped manually.")
    except Exception as e:
        print(f"Error: {e}")


def main():
    adb_output = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
    devices_list = adb_output.stdout.split('\n')
    if len(devices_list) > 1:
        first_device = devices_list[1].split('\t')[0]
    else:
        print("No devices Found at ADB.")
        return
    apps = list_apps(first_device)
    if not apps:
        return "No device found"
    app_package_name = select_package(apps)
    print("Hooking started with pakage => " + app_package_name)

    js_script_file = "crypto.js"

    start_frida_script(app_package_name, js_script_file)


if __name__ == "__main__":
    main()
