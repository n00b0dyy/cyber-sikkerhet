import pandas as pd
import os

def convert_xlsx_to_csv(xlsx_path, csv_path):
    """
    This function converts an Excel file (.xlsx) to a CSV file (.csv) with UTF-8 encoding.
    
    Parameters:
    xlsx_path (str): The file path to the input .xlsx file.
    csv_path (str): The file path to the output .csv file.
    
    Raises:
    ValueError: If the Excel file is empty or does not contain the 'Engelsk' column.
    """
    
    # Read the .xlsx file using pandas
    df = pd.read_excel(xlsx_path, engine='openpyxl')
    
    # Check if the dataframe is empty or if it lacks the 'Engelsk' column
    if df.empty or 'Engelsk' not in df.columns:
        raise ValueError("No translated data in .xlsx")
    
    # Check if the CSV file already exists
    if os.path.exists(csv_path):
        print(f'The file {csv_path} already exists. Overwriting the file...')
    else:
        print(f'The file {csv_path} does not exist. Creating a new file...')
    
    # Save the dataframe to a .csv file with UTF-8 encoding
    df.to_csv(csv_path, index=False, encoding='utf-8')
    
    print(f'The file {csv_path} has been successfully saved.')

def main():
    """
    Main function to define file paths and call the conversion function.
    """
    
    # Define the paths for the input .xlsx file and the output .csv file
    xlsx_path = r'your_path_to_file.xlsx'
    csv_path = r'your_path_to_file.csv'
    
    # Call the function to convert the .xlsx file to a .csv file
    convert_xlsx_to_csv(xlsx_path, csv_path)

if __name__ == "__main__":
    """
    The entry point of the script. Calls the main function if the script is run directly.
    """
    main()

