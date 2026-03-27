General Tech Stack:
Python, use SQLite, minimize other library usages to a minumum.

Coding Style:
Maintain clean code format, minimize nested functions, concise variables,
helper functions when needed, etc..

Behavior:

When the app starts, the user should be greeted with ho mnay questions they would like, which would then randomly select questions from the question bank.

Questions:
The questions should then be selected from a question database and outputted in a json file
that looks like this:

{
  "questions": [
    {
      "question": "What keyword is used to define a function in Python?",
      "type": "multiple_choice",
      "options": ["func", "define", "def", "function"],
      "answer": "def",
      "category": "Python Basics",
      "hint": "Its not func or function"
    },
    {
      "question": "A list in Python is immutable.",
      "type": "true_false",
      "answer": "false",
      "category": "Data Structures",
      "hint": "Can we change a value in a python list?"
    },
    {
      "question": "What built-in function returns the number of items in a list?",
      "type": "short_answer",
      "answer": "len",
      "category": "Python Basics",
      "hint": "It a short form of length"
    },
    {
      "question": "How do we get the values of a dictionary?",
      "type": "multiple_choice",
      "options": ["dict.values()", "dict.val()", "dict.keys()", "dict.v()"],
      "category": "Data structures",
      "hint": "Keys are not values"
    }
    {
      "question": "How do we hash classes",
      "type": "multiple_choice",
      "options": ["Define Hash in a class", "Call hash on the class", "Cast class into a string", "I don't know, I'm lost"],
      "category": "Classes",
      "hint": "Hash function only takes in immutable types"
    }
  ]
}

Files:
There should be a database for the quiz questions (quiz.db), that should contain quiz problems. These are then to be used when generating random quiz problems.

There should be a (user.db) which contain user logins (username, password) as well as the performance of the user on past quizzes.



Errors:

1. The user should only be able to enter whole number > 0 when asking to generate problems. If the user does not, reprompt the user to enter another number.

2. If the Json file is missing, refetch and if its missing again, tell the user to reprompt and/or restart the application.

3. If the user tries logging with a invalid login, give the user 3 tries before exitting the application. User shouldn't be able to brute force lgoins.

4. If the user answers the questions in a invalid format, reprompt the user and note ho the answer should be answered with.

Required features:
1. A local login system that prompts users for a username and password (or allows them to enter a new username and password). 

2. The passwords should not be easily discoverable.

3. A score history file that tracks performance and other useful statistics over time for each user. This file should not be human-readable and should be relatively secure. (This means someone could look at the file and perhaps find out usernames but not passwords or scores.)

4. Users should somehow be able to provide feedback on whether they like a question or not, and this should inform what questions they get next.

5. The questions should exist in their own human-readable .json file so that they can be easily modified. (This lets you use the project for studying other subjects if you wish; all you have to do is generate the question bank.)

Features;
Create a hint system that deducts point but still give the users a opportunity to answer the question.

