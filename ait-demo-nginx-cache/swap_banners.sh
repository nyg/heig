#!/usr/bin/env sh
# Swap banners to simulate a change in the resource file.

cd assets || exit

mv banner.jpg tmp.jpg
mv banner.other.jpg banner.jpg
mv tmp.jpg banner.other.jpg
