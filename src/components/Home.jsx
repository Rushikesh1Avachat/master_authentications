import axios from 'axios'
import React from 'react'
import { Link, useNavigate } from 'react-router-dom'

const Home = () => {
    const navigate=useNavigate()
    axios.defaults.withCredentials=true
    const handleLogout=()=>{
       axios.get("https://mastering-authentication-gcf6.vercel.app/auth/logout")
       .then(res=>{
        if (res.data.status) {
            navigate("/login")
        }
       }).catch(err=>{

       }) 
    }
  return (
    <div>
      <button><Link to="/dashboard">Dashboard</Link></button> 
      <br />  <br />
      <button onClick={handleLogout}><Link to="/logout">Logout</Link></button>   
    </div>
  )
}

export default Home