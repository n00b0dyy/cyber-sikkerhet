import random as r
from turtle import Turtle, Screen
import time

# List of colors to be used for random car coloring.
COLORS = ["red", "orange", "yellow", "green", "blue", "purple"]

# Initial speed for car movement.
STARTING_MOVE_DISTANCE = 5

# Value by which the speed increases after each level.
MOVE_INCREMENT = 5

# Initialize the game screen.
screen = Screen()

# CarManager class, responsible for managing cars.
class CarManager:
    def __init__(self):
        """
        Initializes the CarManager by creating an empty list of cars and setting the initial speed to STARTING_MOVE_DISTANCE.
        """
        self.cars = []  # List to store all cars.
        self.car_speed = STARTING_MOVE_DISTANCE  # Speed at which cars move.

    def create_car(self):
        """
        I HAD BIG ISSUES WITH THE GAME'S SMOOTHNESS. I TRIED TIME.SLEEP(), BUT IT COMPLETELY RUINED THE GAMEPLAY. 
        TURNED OUT THAT SIMPLY GENERATING A CAR WITH A 1/4 CHANCE EVERY 0.1 SECONDS SOLVES THE ISSUE AND DOESN'T INTERFERE 
        WITH THE GAME'S REFRESH RATE, WHICH NEEDS TO BE HIGH FOR SMOOTH TURTLE MOVEMENT, BUT WOULD NEED TO BE LOWER 
        IF I USED TIME.SLEEP() FOR CAR GENERATION FREQUENCY.

        Creates a new car at a random moment if the condition is met.
        """
        random_chance = r.randint(1, 4)  # Randomly generates a number to determine whether to create a new car.
        if random_chance == 1:  # There is a 1 in 7 chance that a new car will be created.
            # Creating a new Turtle object representing the car.
            new_car = Turtle("square")
            new_car.shapesize(stretch_wid=1, stretch_len=2)  # Sets the size of the car.
            new_car.penup()  # Lifts the pen to prevent leaving a trace while drawing.
            new_car.color(r.choice(COLORS))  # Randomly selects a car color from the COLORS list.
            random_y = r.randint(-250, 250)  # Randomly generates the Y position of the car.
            new_car.goto(300, random_y)  # Sets the car's starting position at the right edge of the screen.
            self.cars.append(new_car)  # Adds the car to the cars list.

    def detect_collision(self, turtle):
        """
        Checks if there has been a collision between the turtle and a car.
        """
        for car in self.cars:
            if turtle.distance(car) < 21:  # Checks the distance between the turtle and the car.
                return True  # Returns True if there has been a collision.
        return False  # Returns False if there has been no collision.

    def move_cars(self):
        """
        Moves all cars on the screen to the left.
        """
        for car in self.cars:
            car.backward(self.car_speed)  # Moves the car to the left by the speed value.

    def speed_up(self):
        """
        Increases the speed of the cars after reaching a new level.
        """
        self.car_speed += MOVE_INCREMENT  # Increases car speed by MOVE_INCREMENT.
