import React, {useState} from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import axios from 'axios'
import "../App.css"
const ResetPassword = () => {
    const [password, setPassword]=useState("")
    const {token}=useParams()
    const navigate=useNavigate()
    const handleSubmit=(e)=>{
        e.preventDefault()
        axios.post("http://localhost:3000/auth/reset-password" + token,{ password} )
        .then((response)=> {
          if(response.data.status){
            alert("check your email")
            navigate("/login")
          }
          console.log(response);
          
     console.log(response.data);
     
        })
        .catch((err)=> console.log(err))
      }
  return (
    <div className='sign-up-container'>
    <form className='sign-up-form' onSubmit={handleSubmit}>
       <h2>Reset Password</h2>
       <label htmlFor="password"> New Password</label>
       <input type="password" placeholder='Password' onChange={(e)=>setPassword(e.target.value)}/>
        <button type='submit'>Reset</button>
    </form>
</div>
  )
}

export default ResetPassword