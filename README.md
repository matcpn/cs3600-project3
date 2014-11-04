Milestone README

Our approach for the milestone was to set up the data structures for the header. We made a barebones struct for the header that had all of the bitfields set correctly to how big the unsigned ints needed to be to be thrown together for the header. We then created a scalable and concise helper function for parsing the arguments. We planned on doing the extra credit, so we added in if clauses and statements for that too, but we won't be touching them today. 

To parse the arguments we had a few disagreements on how to structure and design the functions that would be doing dynamic allocation, as we were thinking in different mindsets. We ended up agreeing on one way over another arbitrarily as both the solutions we would think of would work, with just about the same amount of work. 

We then took a break to prepare dinner and to eat snacks.

We then realized that the way we were parsing the arguments required us to know the length of the domain name to create the data structure for holding the address. We realized that this was just not going to work, and had to rework our approach to parsing the arguments.

Afterwards, we realized our tests were all failing because we never wrote the line to print the packet, cause we're bad at this apparently. 

The last thing we did, that is part of our approach was making the size of the packet too small, which meant we were losing data and not printing out everything we needed.
