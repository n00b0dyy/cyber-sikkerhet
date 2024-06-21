


from tkinter import *
import random
import csv

BG = "#B1DDC6"


window = Tk()
window.title("Flash Card")
window.geometry("850x600")
window.config(padx=50, pady=50, bg=BG)

image_card_back = PhotoImage(file="your_path_to/card_back.png")
image_card_front = PhotoImage(file="your_path_to/card_front.png")

card_canvas = Canvas(window, width=500, height=300, highlightthickness=0)
card_canvas.config(bg=BG)

image_front = card_canvas.create_image(250, 150, image=image_card_front)
image_back = card_canvas.create_image(250, 150, image=image_card_back)

card_title = card_canvas.create_text(250, 100, text="Title", font=("Arial", 20, "italic"))
card_word = card_canvas.create_text(250, 150, text="Word", font=("Arial", 60, "bold"))

image_correct_button = PhotoImage(file="your_path_to/right.png")
iknow_button = Button(image=image_correct_button, highlightthickness=0)

image_wrong_button = PhotoImage(file="your_path_to/wrong.png")
idontknow_button = Button(image=image_wrong_button, highlightthickness=0)

iknow_button.place(x=490, y=400)
idontknow_button.place(x=150, y=400)

card_canvas.place(x=125, y=75)

wordlist = []

with open("your_path_to/Norwegian_English_word_database.csv", "r") as csvfile:
    csvreader = csv.DictReader(csvfile)
    for row in csvreader:
        wordlist.append((row['Norsk'], row['Engelsk']))

random_word_pair = random.choice(wordlist)
card_canvas.itemconfig(card_word, text=random_word_pair[0])

def flip_card():
    if card_canvas.itemcget(image_front, 'state') == 'normal':
        card_canvas.itemconfig(image_front, state='hidden')
        card_canvas.itemconfig(image_back, state='normal')
        card_canvas.itemconfig(card_word, text=random_word_pair[1])
    else:
        card_canvas.itemconfig(image_back, state='hidden')
        card_canvas.itemconfig(image_front, state='normal')
        card_canvas.itemconfig(card_word, text=random_word_pair[0])

card_canvas.bind("<Button-1>", lambda e: flip_card())

def next_word(known):
    global random_word_pair
    if known:
        wordlist.remove(random_word_pair)
    random_word_pair = random.choice(wordlist)
    card_canvas.itemconfig(card_word, text=random_word_pair[0])
    card_canvas.itemconfig(card_title, text="Norsk")
    card_canvas.itemconfig(image_front, state='normal')
    card_canvas.itemconfig(image_back, state='hidden')

iknow_button.config(command=lambda: next_word(True))
idontknow_button.config(command=lambda: next_word(False))

window.mainloop()
