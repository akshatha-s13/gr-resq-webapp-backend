from fastapi import APIRouter, status, HTTPException, Request
from app.schemas.forms.user import SignUpForm, SignInForm
from app.db import query, serializer
from datetime import datetime
from . import utils
from app.core.config import settings
import httpx

router = APIRouter()


@router.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup(form: SignUpForm):
    user = query.get_user(form.email)
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Email already exists')

    user = form.to_db_obj()
    query.put_user(user)
    institution_key = serializer.generate_institution_key(form.institution)
    institution = query.get_institution(form.institution)

    author = {
        'first_name': user['FirstName'],
        'last_name': user['LastName'],
        'institution': user['Institution']['Name']
    }
    with httpx.Client(base_url=settings.GSA_DATABASE_API) as client:
        res = client.post('/authors', json=author)

    if not institution:
        query.put_institution({
            'PK': institution_key['PK'],
            'SK': institution_key['SK'],
            'Name': form.institution
        })

    response = query.put_user(user)
    return {"message": "success"}


@router.post('/signin/token', status_code=status.HTTP_200_OK)
async def signin_with_token(req: Request):
    auth_type, auth_token = req.headers.get('authorization').split()
    if auth_type == 'Bearer':
        data = utils.decode_auth_token(auth_token)
        if data['exp'] < datetime.now().timestamp():
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Token expired')

        user = query.get_user(data.get('email'))
        new_token = utils.assign_auth_token(user)
        author_id = utils.get_author_id(user)
        return {'token': new_token, 'author_id': author_id}
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='No token')


@router.post('/signin/credentials', status_code=status.HTTP_200_OK)
async def signin_with_form(form: SignInForm):
    user = query.get_user(form.email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')
    if not utils.check_password(form.password, user['PasswordHash']):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Incorrect password')
    token = utils.assign_auth_token(user)
    author_id = utils.get_author_id(user)
    return {
        'token': token, 'author_id': author_id
    }

@router.get('/profile/{id}', status_code=status.HTTP_200_OK)
async def profile(id: int):
    with httpx.Client(base_url=settings.GSA_DATABASE_API) as client:
        res = client.get(f'/authors/'+str(id))
    author = res.json()
    return author
