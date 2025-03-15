#!/bin/bash -e

tag="0.0.0"
if git describe --tags --abbrev=0 > /dev/null 2>&1 ; then
  tag="$(git describe --tags --abbrev=0)"
fi
VERSION="$tag-$(git rev-parse --short HEAD)-$(hexdump -n 2 -ve '1/1 "%.2x"' /dev/urandom)"

rm -rf dockerbuild || true
mkdir dockerbuild

cp Dockerfile dockerbuild/Dockerfile-amd64
cp Dockerfile dockerbuild/Dockerfile-arm
cp Dockerfile dockerbuild/Dockerfile-arm64

sed -E 's|FROM alpine|FROM --platform=linux/amd64 alpine|' -i dockerbuild/Dockerfile-amd64
sed -E 's|FROM alpine|FROM  --platform=linux/arm/v7 alpine|'   -i dockerbuild/Dockerfile-arm
sed -E 's|FROM alpine|FROM --platform=linux/arm64/v8  alpine|' -i dockerbuild/Dockerfile-arm64

sed -E 's/GOARCH=/GOARCH=amd64/' -i dockerbuild/Dockerfile-amd64
sed -E 's/GOARCH=/GOARCH=arm/'   -i dockerbuild/Dockerfile-arm
sed -E 's/GOARCH=/GOARCH=arm64/' -i dockerbuild/Dockerfile-arm64

docker build --progress=plain -f dockerbuild/Dockerfile-amd64 -t sequentialread/pow-bot-deterrent:$VERSION-amd64 .
docker build --progress=plain -f dockerbuild/Dockerfile-arm   -t sequentialread/pow-bot-deterrent:$VERSION-arm .
docker build --progress=plain -f dockerbuild/Dockerfile-arm64 -t sequentialread/pow-bot-deterrent:$VERSION-arm64 .

docker push sequentialread/pow-bot-deterrent:$VERSION-amd64
docker push sequentialread/pow-bot-deterrent:$VERSION-arm
docker push sequentialread/pow-bot-deterrent:$VERSION-arm64

export DOCKER_CLI_EXPERIMENTAL=enabled

docker manifest create  sequentialread/pow-bot-deterrent:$VERSION \
  sequentialread/pow-bot-deterrent:$VERSION-amd64 \
  sequentialread/pow-bot-deterrent:$VERSION-arm \
  sequentialread/pow-bot-deterrent:$VERSION-arm64 

docker manifest annotate --arch amd64 sequentialread/pow-bot-deterrent:$VERSION sequentialread/pow-bot-deterrent:$VERSION-amd64
docker manifest annotate --arch arm sequentialread/pow-bot-deterrent:$VERSION sequentialread/pow-bot-deterrent:$VERSION-arm
docker manifest annotate --arch arm64 sequentialread/pow-bot-deterrent:$VERSION sequentialread/pow-bot-deterrent:$VERSION-arm64

docker manifest push sequentialread/pow-bot-deterrent:$VERSION

rm -rf dockerbuild || true