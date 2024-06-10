



"""
This Python script is designed to fetch a list of the most frequently occurring words from a specified webpage and save these words to a CSV file. The script uses the requests library to retrieve the webpage content, BeautifulSoup to parse the HTML, and the csv library to save the data into a CSV file. This automation helps in extracting textual data from the internet for subsequent analysis.
"""

import requests  # Importing the requests library to make HTTP requests
from bs4 import BeautifulSoup  # Importing BeautifulSoup to parse HTML
import csv  # Importing the csv library to save data in CSV format

# URL of the webpage with the word list
url = 'https://en.wiktionary.org/wiki/Wiktionary:Frequency_lists/Norwegian_Bokmål_wordlist' # the script was made specificly for wiktionary.org

# Fetch the webpage content
response = requests.get(url)  # Performing a GET request to the specified URL
response.raise_for_status()  # Check if the request was successful; raises an error if not

# Parse the HTML using BeautifulSoup
soup = BeautifulSoup(response.text, 'html.parser')  # Creating a BeautifulSoup object to parse the HTML from the response

# Find all list elements within <ol>
word_elements = soup.select('#mw-content-text > div.mw-content-ltr.mw-parser-output > ol > li > span > a')
#### Using a CSS selector to find all <a> elements within <span> elements inside <li> within <ol>. To find selector go to the page, click "inspect element", choose an element and click "copy selector", so you can adjust this script for your custom needs. ####

# Process the list of words
words = []  # Creating an empty list to store the words
for element in word_elements:  # Iterating over each found element
    word = element.get_text()  # Extracting the text from the <a> element
    words.append(word)  # Adding the word to the list

# Save the list of words to a CSV file
csv_filename = 'words_list.csv'  # Name of the CSV file
with open(csv_filename, mode='w', newline='', encoding='utf-8') as file:  # Opening the CSV file for writing
    writer = csv.writer(file)  # Creating a writer object to write to the CSV file
    for word in words:  # Iterating over the list of words
        writer.writerow([word])  # Writing each word as a separate row in the CSV file

print(f'The word list has been saved to {csv_filename}')
