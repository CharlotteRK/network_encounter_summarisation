import sys
import re
import json

def main():
	skipped_mis = 0
	skipped_am = 0
	config = loadConfig("/cs/home/ck204/Documents/CS4098/src/inc/configfile.cfg")
	assocs = {}
	for line in sys.stdin:
		line = line.encode('utf-8')
		line = line.decode('latin1')

		#need split char and seg no, regex of id (eg in case its an ip, mac, or named?)
		if(isStart(config, line)):
			line_config = config["start"]
			type = "start"
		elif(isEnd(config, line)):
			line_config = config["end"]
			type = "end"
		else:
			continue
		split_char = line_config["split_char"]
		segno_time = line_config["segno_time"]
		segno_id1 = line_config["segno_id1"]
		segno_id2 = line_config["segno_id2"]
		id1_regex = re.compile(line_config["id1_regex"])
		id2_regex = re.compile(line_config["id2_regex"])
		time_regex = re.compile(line_config["time_regex"])
		#specify in config identification of AP
		if (line_config["id1_is_AP"] == "True"):
			id1_is_AP = True
			id2_is_AP = False
		elif (line_config["id2_is_AP"] == "True"):
			id1_is_AP = False
			id2_is_AP = True
		else:
			id1_is_AP = False
			id2_is_AP = False

		split_line = line.split(split_char)
		time_seg = split_line[segno_time - 1]
		id2_seg = split_line[segno_id2 - 1]
		id1_seg = split_line[segno_id1 - 1]

		time_matches = time_regex.findall(time_seg)
		id1_matches = id1_regex.findall(id1_seg)
		id2_matches = id2_regex.findall(id2_seg)

		if(len(time_matches) < 1 or len(id1_matches) < 1 or len(id2_matches) < 1):
			# print("strict")
			# print(time_matches , id1_matches , id2_matches)
			# print(str(len(time_matches)) + ", " + str(len(id1_matches)) + ", " + str(len(id2_matches)))
			skipped_mis = skipped_mis + 1
			continue
		elif(len(time_matches) > 1 or len(id1_matches) > 1 or len(id2_matches) > 1):
			# print("ambiguous")
			# print(time_matches , id1_matches , id2_matches)
			# print(str(len(time_matches)) + ", " + str(len(id1_matches)) + ", " + str(len(id2_matches)))
			skipped_am = skipped_am + 1
			continue
		else:
			time = time_matches[0]
			id1 = id1_matches[0]
			id2 = id2_matches[0]
			if type == "start":
				assocs[id1] = time;
			else:
				try:
					if(id1_is_AP):
						print(id2 + "," + id1 + "," + str(assocs[id1]) + "," + str(time)+ ",1")
					elif(id2_is_AP):
						print(id1 + "," + id2 + "," + str(assocs[id1]) + "," + str(time)+ ",1")
					del assocs[id1]
				except:
					pass
					#print("found end without start??")
			#need source,destination,start,fin,AP format

	if(skipped_am > 0):
		sys.stderr.write("Ambiguious syslog specification given, skipped " + str(skipped_am) + " entries: output may not be accurate\n")
	if(skipped_mis > 0):
		sys.stderr.write("Strict syslog specification given, skipped " + str(skipped_mis) + " entries: output may not be accurate\n")

def loadConfig(filename):
	config = json.load(open(filename, 'r'))
	try:
		config["start"]["segno_time"] = int(config["start"]["segno_time"])
		config["start"]["segno_id1"] = int(config["start"]["segno_id1"])
		config["start"]["segno_id2"] = int(config["start"]["segno_id2"])
	except:
		sys.stderr.write("Malformed configuration, recieved unexpected non-interger value in start.\n")
		quit(1)
	try:
		config["end"]["segno_time"] = int(config["end"]["segno_time"])
		config["end"]["segno_id1"] = int(config["end"]["segno_id1"])
		config["end"]["segno_id2"] = int(config["end"]["segno_id2"])
	except:
		sys.stderr.write("Malformed configuration, recieved unexpected non-interger value in end.\n")
		quit(1)
	if (config["start"]["id1_is_AP"] == "True" and config["start"]["id2_is_AP"] == "True"):
		sys.stderr.write("Malformed configuration, both devices specified as access points in start.\n")
		quit(1)
	if (config["end"]["id1_is_AP"] == "True" and config["end"]["id2_is_AP"] == "True"):
		sys.stderr.write("Malformed configuration, both devices specified as access points in end.\n")
		quit(1)
	return config

def isStart(config, line):
	#get segments, split on comma
	segments = config["start"]["conditions"]["segments"]
	segments_split = segments.split(',')
	split_char = config["start"]["conditions"]["split_char"]
	split_line = line.split(split_char)
	for segment_no in segments_split:
		try:
			segment_regex = config["start"]["conditions"][segment_no]
			segment_no = int(segment_no)
			if len(split_line) < segment_no :
				return False
			segment = split_line[segment_no - 1]
		except:
			sys.stderr.write("Malformed configuration, start conditions include unresolvable segment number.\n")
			quit(1)
		try:
			segment_regex_comp = re.compile(segment_regex)
			match = segment_regex_comp.match(segment)
		except:
			sys.stderr.write("Malformed configuration, start conditions include unresolvable regex.\n")
			quit(1)
		if not match:
			#print(line + " not matched: " + segment + " doesn't match " + segment_regex)
			return False
	#check for corresponding keys, quit with errormsg if not there
	#loop, int conv., regex corr. seg. -> no  match = false
	#print("MATCHED!!")
	return True

def isEnd(config, line):
	#get segments, split on comma
	segments = config["end"]["conditions"]["segments"]
	segments_split = segments.split(',')
	split_char = config["end"]["conditions"]["split_char"]
	split_line = line.split(split_char)
	for segment_no in segments_split:
		try:
			segment_regex = config["end"]["conditions"][segment_no]
			segment_no = int(segment_no)
			if len(split_line) < segment_no :
				return False
			segment = split_line[segment_no - 1]
		except:
			sys.stderr.write("Malformed configuration, end conditions include unresolvable segment number.\n")
			quit(1)
		try:
			segment_regex_comp = re.compile(segment_regex)
			match = segment_regex_comp.match(segment)
		except:
			sys.stderr.write("Malformed configuration, end conditions include unresolvable regex.\n")
			quit(1)
		if not match:
			#print(line + " not matched: " + segment + " doesn't match " + segment_regex)
			return False
	#check for corresponding keys, quit with errormsg if not there
	#loop, int conv., regex corr. seg. -> no  match = false
	#print("MATCHED!!")
	return True

if __name__ == "__main__":
	sys.stdin.reconfigure(encoding='ascii')
	main()
