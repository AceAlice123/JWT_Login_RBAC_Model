After installing the dependencies (if needed)

Set Environment Variables in  an if needed to set your variables .env

in folder directory Run "npm run ServerOn" Same lettercase as it .


Check and test through the frontend 

Otherwise Use PostMan like Services to make calls to different routes
(Note to keep the frontend seemless we are using a jwt cookie and so jwt token will not be authorised using json format)


Overview  <====>
This project implements a rule-based access control system with three defined roles:

Manager: until token expires (then login again)                             Saved as manager@123 and password:manager
Can view all users  .
Can add new users with rank (can also add admins but not manager).


Admin:  until token expires (then login again)                              Saved as admin@123 and password:admin
Can view all users.


Basic:   until token expires (then login again)                               Saved as basic@123 and password:basic
Can only view their own information.

All users must login to get to home page ===>(And register if needed (basic by default))


