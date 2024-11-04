

from turtle import Turtle 

STARTING_POSITION = (0, -280)
MOVE_DISTANCE = 20
FINISH_LINE_Y = 280


class Player(Turtle):
    def __init__(self):
        super().__init__()
        self.shape("turtle")
        self.shapesize(1)
        self.color("blue")
        self.pencolor("white")
        self.penup()
        self.goto(STARTING_POSITION)
        self.pendown()
        self.setheading(90)

    def go_to_start(self):
        if self.is_at_finish_line:
            self.goto(STARTING_POSITION)


    def go_up(self):
        new_y = self.ycor() + MOVE_DISTANCE 
        self.goto(self.xcor(), new_y)


    def is_at_finish_line(self):
        """Sprawdza, czy gracz przekroczył linię końcową."""
        return self.ycor() > FINISH_LINE_Y
