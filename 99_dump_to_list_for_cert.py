import csv
import os

def read_folder_content(base_folder):
    output_file = 'certlist.csv'
    header = ['from ip', 'to ip', 'from domain', 'to domain', 'from asn', 'to asn']

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(header)
        for root, dirs, files in os.walk(base_folder):
            for file in files:
                if file.endswith('_meta.md'):
                    relative_path = os.path.relpath(root, base_folder)
                    folder_names = relative_path.split(os.sep)
                    folder_names.append(file)
                    
                    if 'to' in folder_names[-4]:
                        part1, part2 = folder_names[-4].split('to', 1)
                        part1 = part1.strip()
                        part2 = part2.strip()
                    else:
                        part1 = part2 = folder_names[-4]

                    with open(os.path.join(root, file), 'r') as f:
                        lines = f.readlines()
                        domain1 = lines[0].split('#')[1].split(':')[0].strip()
                        domain2 = lines[5].split(':')[1].strip()
                    
                    if folder_names[0] == 'cloudflare':
                        continue
                    writer.writerow([folder_names[-2], folder_names[-3], domain1, domain2, part1, part2])

base_folder = 'analysisdump_2025-01-09-15-59/_01_vulnerable/'
read_folder_content(base_folder)