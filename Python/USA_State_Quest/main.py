import turtle
import pandas

# Game screen setup
screen = turtle.Screen()
screen.title("U.S. States Game")
image = "blank_states_img.gif"
screen.addshape(image)  # Adds the U.S. states map image as the background
turtle.shape(image)  # Sets the map as the screen background

# Load state data from CSV file
data_read = pandas.read_csv("50_states.csv")
all_states = data_read.state.to_list()  # Creates a list of all state names
guessed_states = []  # List to store correctly guessed states

# Game loop, runs until the player guesses all 50 states or chooses to exit
while len(guessed_states) < 50:
    # Display input dialog for the player to enter state names
    answer_state = screen.textinput(
        title=f"{len(guessed_states)}/50 States Correct",
        prompt="What's another state's name?"
    )
    
    # Check if the user closed the input dialog
    if answer_state is None:
        break  # Exit the loop if the dialog is closed

    answer_state = answer_state.title()  # Convert response to title case

    # Check if the player selected the "Exit" option to end the game
    if answer_state == "Exit":
        # Generate a list of missing states using list comprehension
        missing_states = [state for state in all_states if state not in guessed_states]
        # Save the missing states to a CSV file
        new_data = pandas.DataFrame(missing_states)
        new_data.to_csv("states_to_learn.csv")
        break

    # Check if the entered state name is on the list of all states
    if answer_state in all_states and answer_state not in guessed_states:
        guessed_states.append(answer_state)  # Add the correctly guessed state to the list
        t = turtle.Turtle()
        t.hideturtle()
        t.penup()  # Lift the pen to prevent drawing lines

        # Find the x and y coordinates of the guessed state on the map
        state_data = data_read[data_read.state == answer_state]
        t.goto(int(state_data.x.iloc[0]), int(state_data.y.iloc[0]))  # Move cursor to the state's coordinates
        t.write(answer_state)  # Write the state name on the map
