import importlib.util

def py_module_available(module_name):
    return importlib.util.find_spec(module_name) is not None

if py_module_available("fastf1"):
    print("fastf1 is available.")
else:
    print("fastf1 is not available.")