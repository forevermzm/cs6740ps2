# define a makefile variable for the java compiler
#
JCC = javac

# define a makefile variable for compilation flags
# the -g flag compiles with debugging information
#
JFLAGS = -g

# typing 'make' will invoke the first target entry in the makefile 
# (the default one in this case)
#
default: Fcrypt.class Encryptor.class Decryptor.class

# this target entry builds the Client.class
#
Fcrypt.class: Fcrypt.java
		$(JCC) $(JFLAGS) Fcrypt.java

Encryptor.class: Fcrypt.java
		$(JCC) $(JFLAGS) Fcrypt.java

Decryptor.class: Fcrypt.java
		$(JCC) $(JFLAGS) Fcrypt.java		

# To start over from scratch, type 'make clean'.  
# Removes all .class files, so that the next make rebuilds them
#
clean: 
		$(RM) *.class