package com.atguigu.shiro;

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Simple Quickstart application showing how to use Shiro's API.
 *
 * @since 0.9 RC2
 */
public class Quickstart {

    private static final transient Logger log = LoggerFactory.getLogger(Quickstart.class);


    public static void main(String[] args) {

        // The easiest way to create a Shiro SecurityManager with configured
        // realms, users, roles and permissions is to use the simple INI config.
        // We'll do that by using a factory that can ingest a .ini file and
        // return a SecurityManager instance:

        // Use the shiro.ini file at the root of the classpath
        // (file: and url: prefixes load from files and urls respectively):
    	// 加载配置文件
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        
        // shiro的安全管理器
        SecurityManager securityManager = factory.getInstance();

        // for this simple example quickstart, make the SecurityManager
        // accessible as a JVM singleton.  Most applications wouldn't do this
        // and instead rely on their container configuration or web.xml for
        // webapps.  That is outside the scope of this simple quickstart, so
        // we'll just do the bare minimum so you can continue to get a feel
        // for things.
        SecurityUtils.setSecurityManager(securityManager);

        // Now that a simple Shiro environment is set up, let's see what you can do:

        // get the currently executing user:
        // 核心代码：获取到当前的Subject对象，代表着当前的用户信息
        Subject currentUser = SecurityUtils.getSubject();

        // Do some stuff with a Session (no need for a web or EJB container!!!)
        // shiro有自己的session管理器
        Session session = currentUser.getSession();
        // 使用方式和HttpSession一致
        // 注意：以后用到session尽量统一成HttpSession
        session.setAttribute("someKey", "aValue");
        String value = (String) session.getAttribute("someKey");
        if (value.equals("aValue")) {
            log.info("Retrieved the correct value! [" + value + "]");
        }
        //////////////////////////////////////////////////////////////////////////////////
        // let's login the current user so we can check against roles and permissions:
        // 判断当前的用户是否被认证，当前的用户是否登录
        if (!currentUser.isAuthenticated()) {
        	// 使用了UsernamePasswordToken包装了用户名和密码
            UsernamePasswordToken token = new UsernamePasswordToken("lonestarr", "vespa");
            token.setRememberMe(true);
            try {
            	// 执行登录，传入的是上面包装好的token
                currentUser.login(token);
            } 
            
            /*catch (UnknownAccountException uae) {
                log.info("---> There is no user with username of " + token.getPrincipal());
                return ;
            } catch (IncorrectCredentialsException ice) {
                log.info("---> Password for account " + token.getPrincipal() + " was incorrect!");
                return ;
            } catch (LockedAccountException lae) {
                log.info("The account for username " + token.getPrincipal() + " is locked.  " +
                        "Please contact your administrator to unlock it.");
            }*/
            // ... catch more exceptions here (maybe custom ones specific to your application?
            catch (AuthenticationException ae) {
            	// 捕获所有shiro认证的异常
            	log.info("---> 认证时发生异常 " + ae.getMessage());
            	return ;
            }
        }

        //say who they are:
        //print their identifying principal (in this case, a username):
        log.info("---> User [" + currentUser.getPrincipal() + "] logged in successfully.");

        //test a role:
        // 判断该用户是否具有某一个角色
        if (currentUser.hasRole("schwartz")) {
            log.info("---> May the Schwartz be with you!");
        } else {
            log.info("Hello, mere mortal.");
        }
        //////////////////////////////////////////////////////////////////////////////////
        
        //test a typed permission (not instance-level)
        // 验证用户的行为
        if (currentUser.isPermitted("lightsaber:weild2")) {
            log.info("---> You may use a lightsaber ring.  Use it wisely.");
        } else {
            log.info("Sorry, lightsaber rings are for schwartz masters only.");
        }

        //a (very powerful) Instance Level permission:
        // 更细力度的行为控制
        if (currentUser.isPermitted("user:delete:1006")) {
            log.info("---->  You are permitted to 'delete' the winnebago with license plate (id) '1005'.  " +
                    "Here are the keys - have fun!");
        } else {
            log.info("---> Sorry, you aren't allowed to drive the 'eagle5' winnebago!");
        }

        //登出
        currentUser.logout();

        System.exit(0);
    }
}
