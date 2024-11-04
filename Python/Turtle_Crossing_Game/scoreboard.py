from turtle import Turtle 

# Font style used for displaying score and game over message
FONT = ("Courier", 24, "bold")

# Scoreboard class, responsible for tracking and displaying the player's level and high score
class Scoreboard(Turtle):
    def __init__(self):
        """
        Initializes the Scoreboard by setting the starting score to 0, reading the high score from the file,
        and updating the scoreboard display on the screen.
        """
        super().__init__()
        self.score = 0  # Player's current score
        self.highscore = self.car_highscore_file_download()  # Assigns high score value read from file
        self.update_score()  # Updates the displayed score

    def update_score(self):
        """
        Clears the previous score display and updates it with the current score and high score.
        """
        self.clear()  # Clears previous text from screen
        self.penup()  # Lifts pen to avoid drawing lines
        self.goto(140, 270)  # Sets position for score display
        self.hideturtle()  # Hides the turtle icon
        self.write(f"LEVEL: {self.score} | HIGH LEVEL: {self.highscore}", align="right", font=("Arial", 14, "bold"))

    def level_up(self):
        """
        Increments the player's score by one level and updates the displayed score.
        """
        self.score += 1  # Increases score by 1
        self.update_score()  # Updates the score display

    def car_highscore_file_download(self):
        """
        Reads the high score from the 'car_highscore.txt' file.
        
        If the file doesn't exist, returns 0 as the high score.
        
        Returns:
            int: High score read from the file, or 0 if the file is not found.
        """
        try:
            with open("car_highscore.txt", "r") as hs:
                return int(hs.read())  # Reads and returns high score from the file
        except FileNotFoundError:
            return 0  # If file not found, returns 0

    def car_highscore_file_update(self):
        """
        Updates the high score in the 'car_highscore.txt' file with the current high score.
        """
        with open("car_highscore.txt", "w") as hs:
            hs.write(str(self.highscore))  # Writes the current high score to the file

    def write_over(self):
        """
        Clears the scoreboard, displays the 'Game Over' message, and shows the final level achieved by the player.
        """
        self.clear()  # Clears the scoreboard
        self.hideturtle()  # Hides the turtle icon
        self.goto(0, 0)  # Sets position for game over message
        self.pendown()  # Puts down the pen for writing
        self.write(f"GAME OVER.\nYOUR LEVEL: {self.score}", font=FONT)  # Displays final score and game over message
