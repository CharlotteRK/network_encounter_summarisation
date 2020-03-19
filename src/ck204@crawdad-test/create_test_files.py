import sys

def main(min, max, lines):
	i = int(min)
	print("source,destination,start,fin,AP")
	for j in range(1, int(lines)):

			print("id0,id" + str(i) + ",100,200,1")
			i = i + 1
			if (i > int(max)):
				i = int(min)

if __name__ == "__main__":
	sys.stdin.reconfigure(encoding='latin1')
	main(sys.argv[1], sys.argv[2], sys.argv[3])
