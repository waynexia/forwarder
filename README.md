# forwarder
Forward message via netfilter.

Assume there have three machine, named A B and C. A and C are connected to B but not connects to each other. This thing can make A and C connected by using B to forward message.

Test environment: three CentOS (kernel 3.10.0) run on VMware, a real openwrt(kernel 4.9.87). GCC version 4.8.5. IP addresses are mentioned in code. Sensitivity rules only covers ICMP type 0&8 (ping request & reply) and only tested these.

WARNING: HARD-CODING

openwrt needs sdk for cross compiling. File struct is built.

## License

This project is licensed under the MIT License - see the [LICENSE](/LICENSE) file for details.