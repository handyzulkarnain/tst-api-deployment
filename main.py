# Nama      : Handy Zulkarnain
# NIM       : 18219060
# Tanggal   : 16 Oktober 2021

############ IMPORTS AND INITIAL CONFIGURE ############
from fastapi import FastAPI, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import json

from fastapi.exceptions import HTTPException

import time
from typing import Dict
import jwt

with open("product.json", "r") as read_file:
    data_product = json.load(read_file)
with open("wishlist.json", "r") as read_file:
    data_wishlist = json.load(read_file)
with open("cart.json", "r") as read_file:
    data_cart = json.load(read_file)
with open("users.json", "r") as read_users_file:
    data_users = json.load(read_users_file)

app = FastAPI(title="API BosBuy: Wishlist & Cart")


############ AUTHENTICATIONS ############
SECRET="b'88d875cda190f0688a829d52dc0911c3a316537205f39f63'"
ALGORITHM="HS256"

def res_access_token(token: str):
    return {
        "access_token": token
    }

def createJWT(user_id: str) -> Dict[str, str]:
    body = {
        "user_id": user_id,
        "expiry_time": time.time() + 1200
    }
    token = jwt.encode(body, SECRET, algorithm=ALGORITHM)
    return res_access_token(token)

def decodeJWT(token: str) -> dict:
    try:
        decoded_token = jwt.decode(token, SECRET, algorithms=[ALGORITHM])
        if (decoded_token["expiry_time"] >= time.time()):
            return decoded_token
        else:
            None
    except:
        return {}


############ AUTHORIZATION ############
class BearerToken(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(BearerToken, self).__init__(auto_error=auto_error)
    
    async def __call__(self, request: Request):
        authCredentials: HTTPAuthorizationCredentials = await super(BearerToken, self).__call__(request)
        if (authCredentials):
            if not (self.verifyJWT(authCredentials.credentials)):
                raise HTTPException(status_code=403, detail="Token is Invalid or Expired!")
            return authCredentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Unable to Authorize: No Credentials Provided!")

    def verifyJWT(self, tokenJWT: str) -> bool:
        tokenIsValid: bool = False
        try:
            body = decodeJWT(tokenJWT)
        except:
            body = None
        if (body):
            tokenIsValid = True
        return tokenIsValid


############ HANDLE USERS ############
def check_user(username: str):
    for user in data_users['users']:
        if username == user['username']:
            return True
    return False

def check_password(password: str):
    for user in data_users['users']:
        if password == user['password']:
            return True
    return False

@app.post("/user/login")
async def login_user(username: str, password: str):
    for user in data_users['users']:
        if (check_user(username)) and (check_password(password)):
            return createJWT(user['username'])
    raise HTTPException (
        status_code=500, detail="Wrong credentials!"
    )


############ CRUD OPERATIONS ############
@app.get("/")
async def root():
    return "Anda sedang berada di halaman awal. Silahkan tambahkan /docs pada akhir url."

@app.get("/product", dependencies=[Depends(BearerToken())])
async def see_all_product():
    return data_product['product']

@app.get("/wishlist", dependencies=[Depends(BearerToken())])
async def see_all_wishlist():
    return data_wishlist['product']

# @app.get("/wishlist/{item_id}", dependencies=[Depends(BearerToken())])
# async def see_wishlist(item_id: int):
#     for item_wishlist in data_wishlist['product']:
#         if (item_wishlist['id'] == item_id):
#             return item_wishlist
#     raise HTTPException(
#         status_code=404, detail="Item wishlist not found!"
#     )

@app.post("/wishlist", dependencies=[Depends(BearerToken())])
async def add_to_wishlist(id_product: int, quantity: int):
    id = 1
    if (len(data_wishlist['product']) > 0):
        # biar efisien kita perlu langsung nambahin ke element terakhir aja
        idLastMember = data_wishlist['product'][len(data_wishlist['product'])-1]['id']
        id = idLastMember + 1
    for (item_product) in data_product['product']:
        if (item_product['id'] == id_product):
            name = item_product['name']
    new_data = {"id":id, "name":name, "quantity":quantity}        
    data_wishlist['product'].append(dict(new_data))
    read_file.close()
    with open("wishlist.json", "w") as write_file:
        json.dump(data_wishlist, write_file, indent=4)
    write_file.close()
    return new_data

@app.delete("/wishlist/{item_id}", dependencies=[Depends(BearerToken())])
async def remove_from_wishlist(item_id: int):
    index = 0
    for item_wishlist in data_wishlist['product']:
        index+=1
        if (item_wishlist['id'] == item_id):
            data_wishlist['product'].pop(index-1)
            read_file.close()
            with open("wishlist.json", "w") as write_file:
                json.dump(data_wishlist, write_file, indent=4)
            write_file.close()
            return {}
    raise HTTPException(
        status_code=404, detail="Item wishlist not found!"
    )

@app.put("/wishlist/{item_id}", dependencies=[Depends(BearerToken())])
async def edit_wishlist(item_id: int, quantity: int):
    for item_wishlist in data_wishlist['product']:
        if (item_wishlist['id'] == item_id):
            item_wishlist['quantity'] = quantity
            read_file.close()
            with open("wishlist.json", "w") as write_file:
                json.dump(data_wishlist, write_file, indent=4)
            write_file.close()
            return f'Updated wishlist for id:{item_id}'
    raise HTTPException(
        status_code=404, detail="Item wishlist not found!"
    )
############ END OF FILE ############