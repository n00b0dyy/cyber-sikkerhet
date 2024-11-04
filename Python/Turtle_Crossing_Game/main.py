import time
from turtle import Screen
from player import Player
from car_manager import CarManager
from scoreboard import Scoreboard

zolw = Player()
scoreboard = Scoreboard()
car_manager = CarManager()

# Screen initialization
screen = Screen()
screen.setup(width=600, height=600)
screen.title("TURTLE CROSSING")
screen.tracer(0)  # Disable screen refresh animation
scoreboard.highscore = int(scoreboard.car_highscore_file_download())
screen.listen()
screen.onkey(zolw.go_up, "Up")

game_is_on = True
while game_is_on:
    try:
        screen.update()  # Refresh the screen
        time.sleep(0.1)  # Wait 0.1 seconds
        car_manager.create_car()  # Create new cars
        car_manager.move_cars()  # Move cars

        # Check if the turtle has reached the finish line
        if zolw.is_at_finish_line():
            zolw.go_to_start()
            scoreboard.level_up()
            car_manager.speed_up()

        # Detect collision between the turtle and cars
        if car_manager.detect_collision(zolw):
            scoreboard.write_over()
            if scoreboard.score > scoreboard.highscore:
                scoreboard.highscore = scoreboard.score
                scoreboard.car_highscore_file_update()
            game_is_on = False

    except Exception as e:
        # Handle error when the window is closed or other unexpected exception
        print(f"Error encountered: {e}. Game ended.")
        game_is_on = False  # Stop the game loop

screen.exitonclick()
