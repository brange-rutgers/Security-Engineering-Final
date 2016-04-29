//This requires 4 ethernet ports total.  2 interfaces and 4 macs will be supplied to the command line

require(library /home/comnetsii/elements/routerport.click);

rp0 :: RouterPort(DEV $dev0, IN_MAC $in_mac0 , OUT_MAC $out_mac0 );
rp1 :: RouterPort(DEV $dev1, IN_MAC $in_mac1 , OUT_MAC $out_mac1 );
mitm :: MITMElement();

rp0->[0]mitm;
rp1->[1]mitm;

mitm[0]->rp0;
mitm[1]->rp1;
