from glob import iglob
import os

def list_yaml_files(directory_path):
    # Pattern for .yaml files
    pattern = os.path.join(directory_path, '**', '*.yaml')
    
    # Iterating and printing each file path
    for file_path in iglob(pattern, recursive=True):
        print(file_path)

    # Pattern for .yml files
    pattern = os.path.join(directory_path, '**', '*.yml')
    
    # Iterating and printing each file path
    for file_path in iglob(pattern, recursive=True):
        print(file_path)

# Example usage
directory_path = './mobsfscan/rules/semgrep'  # Replace with your directory path
list_yaml_files(directory_path)
