if [ $1 ] 
then 
  ./fastboot flash:raw boot $1 ramdisk -b 0x80200000 -c 'console=ttyHSL0,115200,n8 androidboot.hardware=flo user_debug=31 msm_rtb.filter=0x3F ehci-hcd.park=3' 
  exit 1
else
  echo "didn't specify the kernel path: use update-kernel-flash.sh PATH_ZIMAGE"
  exit 1
fi
