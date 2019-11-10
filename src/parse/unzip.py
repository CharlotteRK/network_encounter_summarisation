import gzip
import os
import shutil
import pathlib
from subprocess import call

temp = './temp/'

if __name__ == '__main__':
	for file in os.listdir('../../AcadBldg16/'):
		uncompressed_file = temp + 'uncompressed'
		compressed_file = '../../AcadBldg16/' + file
		pathlib.Path(temp).mkdir(parents=True, exist_ok=True)
		try:
			with gzip.open(compressed_file, 'rb') as file_in:
				with open(uncompressed_file, 'wb') as file_out:
					shutil.copyfileobj(file_in, file_out)
			r = call(["./parse", uncompressed_file])
			if r != 0:
				print("./parse exited with non-zero exit code: " + r)
		except:
			print("File " + compressed_file + " could not be uncompressed, skipping.")
			continue
	shutil.rmtree(temp)