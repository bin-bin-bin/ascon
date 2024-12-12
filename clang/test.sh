#!/bin/sh

if which shasum 2>&1 >/dev/null; then alias sha256="shasum -a256"; fi
if which sha256sum 2>&1 >/dev/null; then alias sha256="sha256sum"; fi

head -c 1073741824 /dev/urandom > ./original
cp ./original ./ascontest
res="$(./ascon --enc --key 0123456789abcdef --nonce 0123456789abcdef --file ./ascontest)"
echo "$res"
if echo -e "$res"|grep -Fq "Tag:"; then
    tag=$(echo -e "$res"|grep -F "Tag:"|grep -Eoi "[0-9A-F]{32}$"|xxd -r -p)
    sha256 ./original
    sha256 ./ascontest
    ./ascon --dec --key 0123456789abcdef --nonce 0123456789abcdef --tag "$tag" --file ./ascontest
    sha256 ./ascontest
fi
rm ./ascontest
rm ./original 