pub mod af_xdp;
pub mod metrics;
pub mod udp;

/*
Safety NOTE
    - When a frame / address has been submitted to the fill queue or tx ring, do not use it again until you have consumed it from either the completion queue or rx ring.

   -  Do not use one UMEM's frame descriptors to access frames of another, different UMEM.
*/
