const express = require('express');
const app = express();
const OAuth2 = require('oauth').OAuth2;
const querystring = require('querystring');
const jwt = require('jsonwebtoken');
const _ = require('lodash');
const request = require("request");
const bodyParser = require('body-parser');
var path = require('path');
const HaravanValidate = require(path.resolve('./haravan-validate'));


const config = {
  response_mode: 'form_post',
  url_authorize: 'https://accounts.haravan.com/connect/authorize',
  url_connect_token: 'https://accounts.haravan.com/connect/token',
  grant_type: 'authorization_code',
  nonce: 'abc123',
  response_type: 'code id_token',
  app_id: '91d0f91d09a4e09c90e6ec230ef048a9',
  app_secret: '68c4886705da5a188755310b7aa41c803885bea6c26f4bc250a2b487a501ad55',
  scope_login: 'openid profile email org userinfo grant_service',
  scope: 'offline_access openid profile email org userinfo com.read_products web.write_themes web.read_themes',
  // login_callback_url: 'http://localhost:3000/install/login',
  // login_callback_url: 'https://obscure-falls-14538.herokuapp.com/install/login',
  login_callback_url: 'https://protected-springs-69237.herokuapp.com/install/login',
  // install_callback_url: 'http://localhost:3000/install/grandservice',
  // install_callback_url: 'https://obscure-falls-14538.herokuapp.com/install/grandservice',
  install_callback_url: 'https://protected-springs-69237.herokuapp.com/install/grandservice',
  // install_callback_url: 'https://hidden-peak-00592.herokuapp.com/install/grandservice',
  webhook: {
    hrVerifyToken: 'j8I6FsDVOqAZhWDnwgTIXn5fxaFbp1wy',  //https://randomkeygen.com/ (CodeIgniter Encryption Keys)
    subscribe: 'https://webhook.haravan.com/api/subscribe'
  },
};


// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));

// parse application/json
var haravanValidate = new HaravanValidate(config.app_secret);
app.use(haravanValidate);
app.use(bodyParser.json());



function buildUrlLogin() {
  let objQuery = {
    response_mode: config.response_mode,
    response_type: config.response_type,
    scope: config.scope_login,
    client_id: config.app_id,
    redirect_uri: config.login_callback_url,
    nonce: config.nonce
  };
  let query = querystring.stringify(objQuery);
  return `${config.url_authorize}?${query}`;
}

function buildUrlInstall() {
  let objQuery = {
    response_mode: config.response_mode,
    response_type: config.response_type,
    scope: config.scope,
    client_id: config.app_id,
    redirect_uri: config.install_callback_url,
    nonce: config.nonce
  };
  let query = querystring.stringify(objQuery);
  return `${config.url_authorize}?${query}`;
}

function getToken(code, callback_url) {
  return new Promise((resolve => {
    try {
      let params = {};
      params.grant_type = config.grant_type;
      params.redirect_uri = callback_url;

      let _oauth2 = new OAuth2(
        config.app_id,
        config.app_secret,
        '',
        config.url_authorize,
        config.url_connect_token,
        ''
      );

      _oauth2.getOAuthAccessToken(code, params, (err, accessToken, refreshToken, param_token) => {
        if (err) {
          console.log('error', err);
          resolve();
        } else {
          console.log('param_token', param_token);
          resolve(param_token)
        }
      });
    } catch (error) {
      console.log('error', error);
      return resolve();
    }
  }))
}

function getUserFromDecodeJwt(params) {
  try {
    let userHR = jwt.decode(params.id_token);
    if (!_.isObjectLike(userHR)) {
      return {
        is_error: true,
        message: 'Get User Info Failed'
      };
    }
    if (!userHR.id) {
      userHR.id = userHR.sub;
    }
    return userHR;
  } catch (e) {
    return {
      is_error: true,
      message: `Get User Info Failed ${e.message}`
    };
  }
}

function getShop(access_token) {
  return new Promise(resolve => {
    let options = {
      method: 'GET',
      url: 'https://apis.haravan.com/com/shop.json',
      headers:
        {
          authorization: `Bearer ${access_token}`,
          'Content-Type': 'application/json'
        },
      json: true
    };

    request(options, function (error, response, body) {
      if (error) throw new Error(error);
      console.log(body);
      resolve(body)
    });
  })
}
// https://raw.githubusercontent.com/ktpm489/haravan-plugin/fixMobl/contain/js/configskin.js
// https://raw.githubusercontent.com/ktpm489/haravan-plugin/fixMobl/contain/js/renderData.js
// https://docs.haravan.com/blogs/api-reference/1000018001-asset
// https://github.com/ktpm489/haravan-plugin/blob/fixMobl/contain/js/skin.js
// https://docs.haravan.com/blogs/omni/tutorial-use-scope
function getThemeShop(access_token) {
  return new Promise(resolve => {
    let options = {
      method: 'GET',
      url: 'https://apis.haravan.com/web/themes.json',
      headers:
        {
          authorization: `Bearer ${access_token}`,
          'Content-Type': 'application/json'
        },
      json: true
    };

    request(options, function (error, response, body) {
      if (error) throw new Error(error);
      console.log(body);
      resolve(body)
    });
  })
}

/*** DEMO TEMPLATE
{
  "asset": {
    "key": "assets/bg-body.gif",
    "src": "http://apple.com/new_bg.gif"
  }
}
***/

function postThemeData(access_token, id, name ='' , link = '') {
  let currentData = {
    "asset": {
      "key": `${name}`,
      "value": link
    }
  }
  // let bodyData = JSON.stringify(currentData)
  let bodyData = currentData
  return new Promise(resolve => {
    let options = {
      method: 'PUT',
      url: `https://apis.haravan.com/web/themes/${id}/assets.json`,
      headers:
      {
        authorization: `Bearer ${access_token}`,
        'Content-Type': 'application/json'
      },
      body: bodyData,
      json: true
    };
    console.log('option', options)

    request(options, function (error, response, body) {
      if (error) throw new Error(error);
      console.log(body);
      resolve(body)
    });
  })
}

app.get('/install/login', (req, res) => {
  let url = buildUrlLogin();
  res.redirect(url);
});

app.post('/install/login', async (req, res) => {
  let code = req.body.code;
  if (!code) {
    return res.send('Code not found in request');
  }
  let param_token = await getToken(code, config.login_callback_url);
  if (!param_token) {
    return res.send('Something went wrong!').status(400);
  }
  let userHR = getUserFromDecodeJwt(param_token);
  if (userHR.is_error) {
    return res.send(userHR.message).status(400);
  }

  if (!userHR.id || !userHR.orgname) {
    return res.send('Can not find user or org').status(400);
  }
  userHR.isRoot = 0;
  if (userHR.role) {
    if (_.isString(userHR.role)) {
      userHR.isRoot = userHR.role == 'admin' ? 1 : 0;
    } else {
      userHR.isRoot = userHR.role.includes('admin') ? 1 : 0;
    }
  }

  // Check database shop with userHR.orgid had exists in database and app not removed
  // if had shop and not removed then go to app
  // else if no shop or shop had removed then check
  // if userHR is root then call url install app
  // else response error not have access

  //under is case no shop or shop had removed
  if (userHR.isRoot) {
    let url = buildUrlInstall();
    res.redirect(url);
  } else {
    return res.send('You are not authorized to access this page!').status(401);
  }
});

app.post('/install/grandservice', async (req, res) => {
  let code = req.body.code;
  try {
    if (!code) return res.send('Code not found in request');
    let param_token = await getToken(code, config.install_callback_url);
    if (!param_token) return res.send('Something went wrong!').status(400);
    let userHR = getUserFromDecodeJwt(param_token);
    if (userHR.is_error) return res.send(userHR.message).status(400);
    if (!userHR.id || !userHR.orgname) return res.send('Can not find user or org');
    let authorizeInfo = {
      access_token: param_token.access_token,
      refresh_token: param_token.refresh_token,
      expires_in: param_token.expires_in
    };

    // authorizeInfo can save to database shop for reuse later

    //test request shop.json
    let shopData = await getShop(authorizeInfo.access_token);
    // add theme data
    
    let themeResult = await getThemeShop(authorizeInfo.access_token) 
    console.log('themeResult',themeResult)
    let mainTheme = getMainTheme(themeResult)
    console.log('mainTheme',mainTheme)
    if (mainTheme) {
      // to do post here
      // let postItemAssets = await postThemeData(authorizeInfo.access_token, mainTheme.id, 'snippets/beautys.liquid' ,'');
      // await postThemeData(authorizeInfo.access_token, mainTheme.id, 'snippets/beauty.liquid', '<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script><link rel="stylesheet" href="https://raw.githack.com/ktpm489/haravan-plugin/demo/contain/css/index.css"></head><body><div id="b-placeholder"></div><script>$(function(){$("#b-placeholder").load("https://raw.githack.com/ktpm489/haravan-plugin/demo/contain/skin.html");});</script></body></html>')
      await  postThemeData(authorizeInfo.access_token, mainTheme.id, 'snippets/skinai-plugin.liquid','<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"> <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script> <link rel="stylesheet" href="https://raw.githack.com/ktpm489/haravan-plugin/demoV10/contain/css/index.css"></head><body><div id="b-placeholder"></div> <script>$(function(){$("#b-placeholder").load("https://raw.githack.com/ktpm489/haravan-plugin/demoV10/contain/skin.html");});</script> </body></html>' )
    }
    
    // res.send(shopData);
    // res.redirect(url);
    res.redirect('https://omnipower.haravan.com')
  //   res.writeHead(302 , {
  //     'Location' : 'https://omnipower.haravan.com' // This is your url which you want
  //  });
  //  res.end();

    //if have use webhook, you need subscribe webhook with org token to use
    await subscribe(authorizeInfo.access_token);
  } catch (err) {
    return res.send(err);
  }
});

//--------------------------------------Webhook-----------------------------------//
async function subscribe(access_token) {
  return new Promise(resolve => {
    try {
      let options = {
        method: 'POST',
        url: config.webhook.subscribe,
        headers: {
          authorization: `Bearer ${access_token}`,
          'Content-Type': 'application/json'
        }
      };

      request(options, function (error, response, body) {
        if (error) {
          console.log(error);
        }
        console.log('subscribe webhook success');
        resolve();
      });
    } catch (e) {
      console.log(e);
      resolve();
    }
  })
}


app.get('/webhooks', (req, res) => {
  var verify_token = req.query['hub.verify_token'] || "";
  var hrVerifyToken = config.webhook.hrVerifyToken || "";
  if (verify_token != hrVerifyToken) {
    return res.sendStatus(401);
  }
  res.send(req.query['hub.challenge']);
});

function webhookValidate(req, res, next) {
  let shop = req.headers['x-haravan-org-id'] || '';
  let signature = req.headers['X-Haravan-Hmacsha256'] || '';
  let topic = req.headers['x-haravan-topic'] || '';

  if (!shop || !signature || !topic) {
    return res.sendStatus(401);
  }

  if (!req.fromHaravan(config.app_secret)) {
    return res.sendStatus(401);
  }

  next();
};

app.post('/webhooks', webhookValidate, (req, res) => {
  let topic = req.headers['x-haravan-topic'] || '';
  let org_id = req.headers['x-haravan-org-id'] || '';
  switch (topic) {
    case "product/update": {
      res.sendStatus(200);
      console.log(req.body);
      break;
    }
    default:
      res.sendStatus(200);
      break;
  }
});
//--------------------------------------End Webhook-----------------------------------//

app.use('/', function (req, res) {
  res.redirect('/install/login');
});

app.listen(process.env.PORT || 3000, function () {
  console.log('listening on 3000')
});
// app.listen(3000, function () {
//   console.log('listening on 3000')
// });

/**
 *  Format data
 * {
      "created_at": "2015-03-28T13:31:19-04:00",
      "id": 828155753,
      "name": "Comfort",
      "role": "main",
      "theme_store_id": null,
      "updated_at": "2015-03-28T13:33:30-04:00",
      "previewable": true,
      "processing": false
    } */
function getMainTheme (data) {
  return data && data.themes ? data.themes.find(x => x.role==='main') : undefined
}


// getThemeShop('C0F351C6BEF84DBBE463DD878790CA73B96CA96ADE799BB96C8B2AA346332E1C')
// postThemeData('C0F351C6BEF84DBBE463DD878790CA73B96CA96ADE799BB96C8B2AA346332E1C', '1000667309', 'snippets/beautys1.liquid', '<script async src="https://raw.githubusercontent.com/ktpm489/demo-pluginharavan/main/haravan-validate.js"></script>')
// postThemeData('C0F351C6BEF84DBBE463DD878790CA73B96CA96ADE799BB96C8B2AA346332E1C', '1000667309', 'snippets/skinai-plugin.liquid','<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"> <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script> <link rel="stylesheet" href="https://raw.githack.com/ktpm489/haravan-plugin/demoV10/contain/css/index.css"></head><body><div id="b-placeholder"></div> <script>$(function(){$("#b-placeholder").load("https://raw.githack.com/ktpm489/haravan-plugin/demoV10/contain/skin.html");});</script> </body></html>' )
// postThemeData('C0F351C6BEF84DBBE463DD878790CA73B96CA96ADE799BB96C8B2AA346332E1C', '1000667309', 'snippets/skinai12.liquid','<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"> <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script> <link rel="stylesheet" href="https://raw.githack.com/ktpm489/haravan-plugin/demoV10/contain/css/index.css"></head><body><div id="b-placeholder"></div> <script>$(function(){$("#b-placeholder").load("https://raw.githack.com/ktpm489/haravan-plugin/demoV10/contain/skin.html");});</script> </body></html>' )