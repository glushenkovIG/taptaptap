# Fantom task 1
# Team: Serotonin Syndrome

How to build: ```make```

How to launch: copy `conf.txt.example` into `conf.txt` and make some changes, see `Config format`

To start recording run: ```./main record conf.txt```

Stop recording: `Ctrl+C`.

Replay node with `i` index: ```./main replay conf.txt i```

#Config format
===
Every line in a config should be or empty or commented (begin with #) or should be a command. Command has the following format:

<key> <argument>

it means firsly we have a `key`, then some space symbols, then `argument`.

Now the following keys are supported:

timed (optional, `false` by default) -- should be send data blocks in the same speed as during recording. Can be `true` or `false`

dump_file (necessary) -- dump file path.

subnet (necessary) -- subnet for our virtual network, for example 10.1.0.0/24

node (at least two needed) -- next node command, will be sended to /bin/sh. For example,

 urxvt -e /bin/bash &

-- run our terminal emulator.

Which nodes should be registered in conf.txt instead of my terminal emulator - I'll write later.

So how does it work. When recording, it puts each node in a separate network namespace, and creates a separate TUN device for each node. The program itself acts as a multiplexer - it receives a packet from the device, parses it, records traffic, and sends it to where it should go - to the TUN device of another node.

When replaying in the namespace, it is not the processes of the nodes that are created, but the forks of our process, which, like actors in the theater (or, rather, in the Truman show?), Play roles in front of one node.
