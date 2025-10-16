# DPI
Deep Packet Inspection

## Build Instructions

### Debug Mode
```
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
```

### Release Mode
```
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
```

## Important Notes
 - Make sure to change CONFIG_FILE_PATH macro in include/ConfigReader.hpp to actual path of config file.
 - Make sure the paths defined in Configuration.ini are correct.
 - Make sure build instructions are followed from within the DPI folder.