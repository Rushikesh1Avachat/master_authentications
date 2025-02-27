import React, { useState } from 'react'
import "../App.css"
import axios from "axios"
import {Link, useNavigate}from "react-router-dom"
const Signup = () => {
    const [username, setUserName]=useState("")
    const [email, setEmail]=useState("")
    const [password, setPassword]=useState("")
    const navigate=useNavigate()
    const handleSubmit=(e)=>{
      e.preventDefault()
      axios.post("http://localhost:3000/auth/signup",{username, email, password} )
      .then((response)=> {
        if(response.data.status){
          navigate("/login")
        }
   
      })
      .catch((err)=> console.log(err))
    }
  return (

    <div className='sign-up-container'>
        <form className='sign-up-form' onSubmit={handleSubmit}>
            <h2>Sign Up</h2>
            <label htmlFor="username">User Name</label>
            <input type="text" placeholder='User Name' autoComplete='off' onChange={(e)=>setUserName(e.target.value)} />
            <label htmlFor="email">Email</label>
            <input type="email" placeholder='Email'  autoComplete='off' onChange={(e)=>setEmail(e.target.value)} />
            <label htmlFor="password">Password</label>
            <input type="password" placeholder='Password' onChange={(e)=>setPassword(e.target.value)}/>
            <button type='submit'>Sign up</button>
            <p> Have an account <Link to="/login">Login</Link> </p> 

        </form>
    </div>
  
  )
}

export default Signup