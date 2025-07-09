cd /arrowdev/cpp

rm -rf build && mkdir build && cd build
cmake -GNinja \
  -DARROW_WITH_SNAPPY=ON \
  -DCMAKE_INSTALL_PREFIX=$(pwd)/install \
  -DARROW_PARQUET=ON \
  -DPARQUET_REQUIRE_ENCRYPTION=ON \
  -DARROW_COMPUTE=ON \
  -DARROW_PYTHON=ON \
  -DCMAKE_BUILD_TYPE=Debug \
  ..
ninja install

