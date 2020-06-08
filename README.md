# Overview
There is a lot of current research which requires data about the usage of wireless networks, however a lot of time and effort must be spent separating out useful information from the huge amount of data now collected by wireless network monitoring. The amount of data sent over wireless networks will only continue growing in years to come. During this project a tool has been developed which enables relevant information for network mobility research to be extracted from multiple input sources and converted to a single, more manageable output. Processing stages in the tools data flow have been separated into individual components to enable easy expansion to new input formats in the future, with the current tool handling only tcpdump and syslog input. The minimum file size reduction seen on real tcpdump traces was found to be 99.992\%. The tool which has been developed has a quadratic dependency of execution time on the number of device-to-device associations in the input data. This dependency could become an issue if very large data sets need to be used with it.

# Usage
The tool is run by using a BASH script ```summarise.sh```,  this script can be found inthe  src  directory.   When  a  user  runs  the  script  they  must  use  either  the  ‘merge’  or‘summary’ command and have several optional arguments to use for setting variousruntime parameters.

Commands:
* ```merge```:  used to combine all of the summary files in the input directory.  An error will be thrown if the input directory contains .txt or .csv files which are not in the expected format.  The output given will be in the same format as the input summaries.  Only the -i and -o options will effect this command.
* ```summary```:  used to summarise tcpdump or syslog traces into one of the available summary output formats.  The -c option will only be used if the -f option is setto ‘syslog’.

Options:
* ```-f <<inputformat>>``` is used to specify the format of the input files.  Currently only ‘syslog’ and ‘tcpdump’ are valid formats to use with this flag, and if the flag is not used then the tool assumes a default format of tcpdump pcap output.
* ```-i <<inputdir>>``` is used to specify an input directory.  This is the directory which will be searched for appropriate input files for the tool, if the -i flag is not set then the current directory is used as a default.
* ```-o <<outputfile>>``` is used to specify a path for the output file.  If the flag is not  used  then  the  script  will  create  a  file  in  the  current  directory  with  name of  format  YYYY-MM-DD_hh-mm-ss_summary.csv  (with  the  current  date  and time used where appropriate).
* ```-c <<configfile>>``` is  used  to  specify  a  configuration  file  for  use  during  processing.  If a configuration file is not required to process input of the specified format then the configuration file will be ignored, but a warning will be output to terminal.  If no configuration file is specified when the format demands it, an error message is output to stderr and the script will exit immediately.
* ```-t <<outputtype>>``` is  used  to  specify  which  output  format  of  summary  to produce.  Currently only ‘events’,  ‘eventsmaintainidentifiers’,  or ‘encounters’ are valid output types to use here. By default if this flag is not used an encounter summary will be produced containing the average length and the frequency of encounters between each pair of mobile devices. 

The structure of the command should be ```./summarise <command> <options>```
