#####


 	To make a root volume for EBS, you need to replicate the following GPT
	
	
	Device       Start      End Sectors Size Type
	/dev/xvdg1    2048     4095    2048   1M BIOS boot
	/dev/xvdg2    4096  8392703 8388608   4G Linux filesystem
	/dev/xvdg3 8392704 12587007 4194304   2G Linux filesystem



	fsidk /dev/xvdg
	g= gpt table must be this
	n= new partition
	t= change the typpe (must be BIOS boot)



	format the new partition


	mount to a directory mount /dev/xvdg2 /mnt/myroot/root


        To install grub2-install you must be inside the root with access to boot

 
	mount --bind /dev dev
	mount --bind /proc proc
	mount --bind /sys sys
	chroot .
	[root@centos /]# grub2-install /dev/xvdg   #must be in the block,no PARTITION!!



