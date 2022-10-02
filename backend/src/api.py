from crypt import methods
import os
from turtle import title
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)


db_drop_and_create_all()

# ROUTES

# get drinks
#requires no permission
#lists all available drinks
@app.route('/drinks')
def get_drinks():
    drinks = Drink.query.all()

    formatted_drinks = [drink.short() for drink in drinks]

    return jsonify({
        "success": True,
        "drinks": formatted_drinks
    })


# get drinks details
#requires 'get:drinks-details' permission which is available to manager and barista
# gives details of all drinks if user has permission else raises 422 auth error
@app.route('/drinks-detail')
@requires_auth('get:drinks-details')
def get_drinks_details(payload):
    try:
        drinks = Drink.query.all()

        formatted_drinks = [drink.long() for drink in drinks]

        return jsonify({
            "success": True,
            "drinks": formatted_drinks
        })
    except:
        abort(402)

#create drink
#requires 'post:drinks' permission which is available to manager only
# creates drink if details are available and user has permission else raises 422 auth error

@app.route('/drinks', methods=["POST"])
@requires_auth('post:drinks')
def create_drink(payload):
    body = request.get_json()
    print(body)

    try:
        title = body["title"]
        recipe_json = json.dumps(body["recipe"])
        drink = Drink(title=title,recipe=recipe_json)
        drink.insert()

        return jsonify({
            "success": True,
            "drinks" : [drink.long()]
        })
    except:
        abort(422)


#updating drink
#requires 'patch:drinks' permission which is available to manager only
# updates the drink if found and user has permission else raises 422 auth error
@app.route('/drinks/<int:drink_id>', methods=['PATCH'])
@requires_auth("patch:drinks")
def update_drink(drink_id,payload):
    body = request.get_json()

    drink = Drink.query.filter(Drink.id == drink_id).one_or_none()

    if not Drink:
        abort(404)

    try:
        drink.title = body["title"]
        drink.recipe = body["recipe"]

        drink.update()

        return jsonify({
            "success": True,
            "drinks":[drink.long()]
        })
    except:
        abort(422)


# deleting drink
# requires 'delete:drinks' permission which is only avaliable to managers
# deletes drink if user has permission and drink and found else rasies a 422 auth error
@app.route('/delete/<int:drink_id>', methods=["DELETE"])
@requires_auth("delete:drinks")
def delete_drink(drink_id, payload):

    drink = Drink.query.filter(Drink.id == drink_id).one_or_none()
    if not drink:
        abort(404)
    
    try:
        drink.delete()

        return jsonify({
            "success":True,
            "delete":drink.id
        })
    except:
        abort(422)

# Error Handling


#Error handler 422 Unprocessable
@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422



#Error handler 404 not found
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message":"resource not found"
    },404)


#Error handler 401 Unauthorized
@app.errorhandler(AuthError)
def unauthorised(auth_error):
    return jsonify({
        "success": False,
        "error": auth_error.status_code,
        "message": auth_error.error
    },401)