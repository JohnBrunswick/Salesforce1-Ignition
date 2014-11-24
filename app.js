/*
  S1 Ignition Pack - Supporting Services via Heroku
*/

/***********************************************
/ Setup and inclusion of libs
***********************************************/
var express = require('express');

// Token related libs
var jwt = require('jwt-simple');
var moment = require('moment');
var url = require('url')

// SFDC related libs
var nforce = require('nforce');
var async = require('async');

// SOAP to validate live SFDC user
var jsforce = require('jsforce');

// Postgress related libs
var pg = require('pg');

// Twitter & Faroo related libs
var Client = require('node-rest-client').Client;
var Twit = require('twit');

var analyze = require('Sentimental').analyze,
    positivity = require('Sentimental').positivity,
    negativity = require('Sentimental').negativity;

// Security library
var helmet = require('helmet');

// Instantiate Express server
var express = require('express'),
    cors = require('cors'),
    port = process.env.PORT || 3000,
    app = express();

//var port = process.env.PORT || 3001;
var oauth;

// External service keys (in future store in Heroku)
var newsKey = process.env.NEWSKEY;


// Domains which are allowed by the CORS policy 
// e.g. https://c.na10.visual.force.com
var corsOptions = {
  origin: process.env.CORS
};

app.configure(function(){  
  // If CORS requires adjustment see https://github.com/troygoode/node-cors/ to update
  // the following
  app.use(cors());

  // General Express settings
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.static(__dirname + '/public'));  

  app.use(helmet.hidePoweredBy());
  app.use(helmet.nosniff());
  // These are equivalent:
  //app.use(helmet.xframe());

  // Only let me be framed by people of the same origin:
  app.use(helmet.xframe('deny'));

  //app.use(function(req, res, next) {
  //  res.contentType('application/json');
  //  next();
  //});
  app.set('jwtTokenSecret', process.env.JWT_SECRET);
  //app.use(helmet.contentTypeOptions());
});


var T = new Twit({
    consumer_key:         process.env.TWITTER_CONSUMER
  , consumer_secret:      process.env.TWITTER_CONSUMER_SECRET
  , access_token:         process.env.TWITTER_ACCESS_TOKEN
  , access_token_secret:  process.env.TWITTER_TOKEN_SECRET
})



/* News for the accounts that are being seen within the next 30 days or touched within the last 30 */
var EventWindow = 30;
var AccountWindow = 30;
var twitterCount = 10;

// Wait times in ms to space out API calls and stay within limits from providers
var twitterWaitTime = 35000;
var newsWaitTime = 10000;

/***********************************************
/ End - Setup and inclusion of libs
***********************************************/


/***********************************************
/ Connection to SFDC via REST Setup - used to understand 
  what accounts have upcoming events or have recently
  been viewed - helping to ensure only relevant information
  is brought into S1 Intake
***********************************************/

// use the nforce package to create a connection to salesforce.com
var org = nforce.createConnection({
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  redirectUri: 'http://localhost:' + port + '/oauth/_callback',
  apiVersion: 'v29.0'
});

// authenticate using username-password oauth flow
org.authenticate({ username: process.env.USERNAME, password: process.env.PASSWORD }, function(err, resp){
  
  if(err) {
    console.log('Error: ' + err.message);
  } else {
    console.log('Access Token: ' + resp.access_token);
    oauth = resp;
  }
});

/***********************************************
/ End - Connection to SFDC via REST Setup
***********************************************/


/***********************************************
/ Utilities and XSS prevention methods 
***********************************************/
function escapeHTML(str) {
     str = str + "";
     var out = "";
     for(var i=0; i<str.length; i++) {
         if(str[i] === '<') {
             out += '&lt;';
         } else if(str[i] === '>') {
             out += '&gt;';
         } else if(str[i] === "'") {
             out += '&#39;'; 
         } else if(str[i] === '"') {
             out += '&quot;';                        
         } else {
             out += str[i];
         }
     }
     return out;                    
}

function cleanup(arr, prop) {
    var new_arr = [];
    var lookup  = {};
 
    for (var i in arr) {
        lookup[arr[i][prop]] = arr[i];
    }
 
    for (i in lookup) {
        new_arr.push(lookup[i]);
    }
    return new_arr;
}

Date.prototype.yyyymmdd = function() {         
        var yyyy = this.getFullYear().toString();                                    
        var mm = (this.getMonth()+1).toString(); // getMonth() is zero-based         
        var dd  = this.getDate().toString();                                         
        return yyyy + '/' + (mm[1]?mm:"0"+mm[0]) + '/' + (dd[1]?dd:"0"+dd[0]);
};


function scrubValue(toScrub, intLimiter)
{ 
  if (typeof toScrub != 'undefined') {

    var cleanValue = toScrub.replace(/\W/g, '');
    var intLimiter = (typeof intLimiter === "undefined") ? 0 : intLimiter;

    if (intLimiter == 1)
    {
      if (isNaN(cleanValue)) {
        return '0';
      }
      else {
        return cleanValue;
      }
    }
    else
    {
      return cleanValue;
    }
  }
  else
  {
    return '';
  }
}


function scrubArray(aOriginal)
{
  var scrubbedArray = [];

  try {
    aOriginal.forEach(function(entry) {
      scrubbedArray.push(scrubValue(entry));
    });
  }
  catch(err) {
      console.log(err);
  }  
  return scrubbedArray;
}

process.on('uncaughtException', function(err) {
  console.log('error: ' + err);
});

/***********************************************
/ End - Utility and XSS prevention methods 
***********************************************/





/***********************************************
/ Require auth via JWT Token for any REST endpoints with /api/*
***********************************************/

app.options('/api/*', cors(corsOptions));

app.post('/api/*', cors(corsOptions), function(req, res, next) {

  if ((req.body && req.body.access_token) || req.query.access_token || req.headers["x-access-token"])
  {
    var token = (req.body && req.body.access_token) || req.query.access_token || req.headers["x-access-token"];    
    var user = '';

    if ((req.body && req.body.user) || req.query.user || req.headers["x-access-user"])
    {
      user = (req.body && req.body.user) || req.query.user || req.headers["x-access-user"];
      console.log('user - ' + user);
    }

    if (token) {

      try {
        var decoded = jwt.decode(token, app.get('jwtTokenSecret'))

        if (decoded.exp <= Date.now()) {
          //res.end({error: 'Access token has expired'}, 400);
          res.send(400, { error: "Access token expired" });
        }

        // Check that user matches what was inside the token
        if (decoded.iss == user)
        {
            req.user = user;
            return next();
        }
        else {
          //res.end({error: 'Access denied'}, 400);
          res.send(400, { error: "Access denied" });
        }

      } catch (err) {
        res.send(400, { error: "Access denied" });
      }

    } else {
      res.send(400, { error: "No token found" });
    }
  } else {
    res.send(400, { error: "No token found" });
  }    

});

app.get('/api/*', cors(corsOptions), function(req, res, next) {

  if ((req.body && req.body.access_token) || req.query.access_token || req.headers["x-access-token"])
  {
    var token = (req.body && req.body.access_token) || req.query.access_token || req.headers["x-access-token"];    
    var user = '';

    if ((req.body && req.body.user) || req.query.user || req.headers["x-access-user"])
    {
      user = (req.body && req.body.user) || req.query.user || req.headers["x-access-user"];
      console.log('user - ' + user);
    }

    if (token) {

      try {
        var decoded = jwt.decode(token, app.get('jwtTokenSecret'))

        if (decoded.exp <= Date.now()) {
          //res.end({error: 'Access token has expired'}, 400);
         res.send(400, { error: "Access token expired" });
        }

        // Check that user matches what was inside the token
        if (decoded.iss == user)
        {
            req.user = user;
            return next();
        }
        else {
          res.send(400, { error: "Access denied" });
        }

      } catch (err) {
        res.send(400, { error: "Access denied" });
      }

    } else {
      res.send(400, { error: "No token found" });
    }
  } else {
    res.send(400, { error: "No token found" });
  }

});


app.options('/token', cors(corsOptions));
app.get('/token', cors(corsOptions), function(req, res) {

  if (req.query.sessionId && req.query.serverUrl) {   

    var sessionId = req.query.sessionId;
    var serverUrl = req.query.serverUrl;

    var pattAPIServer = /https:\/\/[a-z].[a-z][a-z][0-9][0-9].visual.force.com\/services\/(S|s)(O|o)(A|a)(P|p)\/(u|c)\/.*/g;

    // Check to make sure that the SOAP URL matches the proper pattern for SFDC
    if(pattAPIServer.test(serverUrl)) {

      // Starting check for user with active session in SFDC
      var jsforce = require('jsforce');
      var conn = new jsforce.Connection({
        serverUrl : serverUrl,
        sessionId : sessionId
      });

      conn.identity(function(err, idenres) {
        if (err) {
          console.log(err);
          res.send('Authentication error', 401)
        }
        else if (idenres.user_id == 'undefined')
        {
          res.send('Authentication error', 401)
        }
        else {
          console.log("user ID: " + idenres.user_id);
          
          // Great, user has successfully authenticated, so we can generate and send them a token.  
          var expires = moment().add('days', 1).valueOf();
          var token = jwt.encode({
              iss: idenres.username,
              exp: expires
            },
            app.get('jwtTokenSecret')
          );
          res.json({
            token : token,
            expires : expires,
            user : idenres.username
          });
        }
      });
    }
    else {
      res.send('Authentication error', 401)
    }
  }
  else
  {
    res.send('Authentication error', 401)
  }

});
/***********************************************
/ End - Require auth via JWT Token for any REST endpoints with /api/*
***********************************************/


 var getTwitterContent = function(handle, nextTweet)
 {

  twitterSearchHandle = '@' + handle.twittername;

  T.get('search/tweets', { q: twitterSearchHandle, count: twitterCount, lang: 'en' }, function(err, data, response) {

    var datarespTwitter = new Array();

    if(data) {
      feed = data.statuses;
      // console.log(feed);

      for(var tweet in feed) {
        tweetdata = new Array();
        tweetdata.title = feed[tweet].text;
        tweetdata.author = feed[tweet].user.screen_name;
        tweetdata.iconlink = '';
        tweetdata.excerpt = '';
        tweetdata.url = feed[tweet].id_str;
        tweetdata.accountname = handle.accountname;
        tweetdata.accountid = handle.accountid;
        tweetdata.type = '1';
        tweetdata.setiment = analyze(feed[tweet].text).score;
        var d = new Date(feed[tweet].created_at);
        tweetdata.publisheddate = d.toISOString();
        tweetdata.twitter_retweet = feed[tweet].retweet_count;
        tweetdata.twitter_favorite = feed[tweet].favorite_count
        datarespTwitter.push(tweetdata);
      }
    }

    // Commit to DB
    async.forEachLimit(datarespTwitter, 1, addCollection, function(err){
       if (err) throw err;
       console.log('+++ Done all tweets processed for ' + handle.accountname);
    });

  })

  // Pace to stay within the Twitter API limits of 15 calls with 15 min
  setTimeout(function() { nextTweet(); }, twitterWaitTime);
}



var addCollection = function(dataresp, nextCollectionAdd) {

  title = escapeHTML(dataresp.title);
  excerpt = escapeHTML(dataresp.kwic);
    
  // Defaults - for news source
  source = 0;
  setiment = 0.0;  
  author = '';
  iconlink = '';
  twitter_retweet = 0;
  twitter_favorite = 0;
  news_vote = 0;

  accountid = dataresp.accountid;
  accountname = escapeHTML(dataresp.accountname);

  if (dataresp.author)
  {
    author = escapeHTML(dataresp.author);
  }
    
  link = escapeHTML(dataresp.url);
  
  if (dataresp.iurl)
  {
    iconlink = escapeHTML(dataresp.iurl);
  }
    
  // Check if Twitter, if so, type = 1
  if (dataresp.type)
  {
    // Twitter
    pubdate = dataresp.publisheddate;
    source = 1;
    setiment = dataresp.setiment;
    twitter_retweet = dataresp.twitter_retweet;
    twitter_favorite = dataresp.twitter_favorite;
  }
  else {
    // Articles
    var d = new Date(dataresp.date).toDateString("yyyy/mm/dd");
    pubdate = d;
    setiment = analyze(dataresp.title).score;
    news_vote = dataresp.votes;
  }

  pg.connect(process.env.DATABASE_URL, function(err, client, done) {

      client.query('INSERT INTO Collector (iconlink, title, excerpt, author, link, accountid, accountname, publisheddate, source, setiment, twitter_retweet, news_vote, twitter_favorite) SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13 WHERE NOT EXISTS (SELECT 1 FROM Collector WHERE title = $14 AND accountid = $15)', [iconlink, title, excerpt, author, link, accountid, accountname, pubdate, source, setiment, twitter_retweet, news_vote, twitter_favorite, title, accountid], function(err, result) {
        
        if(err) {
          console.log('error : did not save ' + err);
          done();
        }
        else {
          console.log('saved : ' + accountname + ', for : ' + title);
          done();
        }

    });
  });

  setTimeout(function() { nextCollectionAdd(); }, 5000);
}

app.options('/api/mapevents', cors(corsOptions));
app.post('/api/mapevents', cors(corsOptions), function(req, res, next) {

  var accounts = '';

  if (req.body.accounts) {
    // Scrub array contents
    var accountArray = scrubArray(req.body.accounts);

    // Flatten the array
    accounts = accountArray.join("','");
  }

  var source = scrubValue(req.body.source, 1); 
  var importance = scrubValue(req.body.importance, 1);
  var mapdata = scrubValue(req.body.mapdata, 1);

  // Get parameter for days ago, if not, fall back to default
  var daysago = req.query.daysago ? scrubValue(req.query.daysago, 1) : 31;
  
  pg.connect(process.env.DATABASE_URL, function(err, client, done) {

    // SELECT * FROM table WHERE id = ANY ($1)

    if (mapdata == '1')
    {
      queryString = 'WITH t1 AS (SELECT accountid, accountname, SUM(twitter_retweet) AS "twitter_retweet", max(twitter_retweet) AS "max_retweet", AVG(setiment) AS "avg_setiment", AVG(twitter_retweet) AS n   FROM collector WHERE publisheddate >= current_date - interval \'31 days\' AND source = 1 AND accountid IN (\'' + accounts + '\')   GROUP BY accountid, accountname) SELECT accountid, accountname, max_retweet, avg_setiment, n as "avg_retweet", 100.0 * twitter_retweet / sum(twitter_retweet + 0.1) over () as "percent_twitter_share" FROM t1;';
      //console.log(queryString);
    }
    else if (importance == '1' && source == '1')
    {
      // Twitter
      queryString = "SELECT *, extract(day from publisheddate) as daysago FROM collector WHERE publisheddate >= current_date - interval '" + daysago + " days' AND source = 1 AND accountid = '" + accounts + "' ORDER BY twitter_retweet DESC LIMIT 3;";
    }
    else if (importance == '1' && source == '0')
    {
      // News
      queryString = "SELECT *, extract(day from publisheddate) as daysago FROM collector WHERE publisheddate >= current_date - interval '" + daysago + " days' AND source = 0 AND accountid = '" + accounts + "' ORDER BY news_vote DESC LIMIT 3;";
    }
    else {
      queryString = "SELECT *, extract(day from publisheddate) as daysago FROM Collector WHERE publisheddate >= current_date - interval '" + daysago + " days' AND accountid IN ('" + accounts + "') LIMIT 20;";
    }
    // JMB - above used to be "any"

    query = client.query(queryString);
    
    var resultCollection = [];

    query.on('error', function(error) {
      //console.log('error: ' + error);
      res.json(resultCollection);
      done();
    });

    query.on('row', function(result) {
    
      if (!result) {
        //done();
      } else {
        //console.log(result);
        resultCollection.push(result);

      }
    });

    //send the results
    query.on('end', function (err, result) {
      res.json(resultCollection);
      done();
    });
  });
});


app.options('/api/getfrequency', cors(corsOptions));
app.get('/api/getfrequency', cors(corsOptions), function(req, res, next) {

  var accountid = scrubValue(req.query.accountid);

  // Get parameter for days ago, if not, fall back to default
  var daysago = req.query.daysago ? scrubValue(req.query.daysago, 1) : 31;

  pg.connect(process.env.DATABASE_URL, function(err, client, done) {

    queryString = '';

    var detailed = scrubValue(req.query.detailed);

    if (detailed)
    {
      queryString = "select to_char(publisheddate, 'YYYY-MM-DD'), count(accountid), source from collector where publisheddate >= current_date - interval '" + daysago + " days' AND accountid = '" + accountid + "' group by to_char(publisheddate, 'YYYY-MM-DD'), source order by to_char(publisheddate, 'YYYY-MM-DD') desc limit 31";
    }
    else
    {
      queryString = "select to_char(publisheddate, 'YYYY-MM-DD'), count(accountid) from collector where publisheddate >= current_date - interval '" + daysago + " days' AND accountid = '" + accountid + "' group by to_char(publisheddate, 'YYYY-MM-DD') order by to_char(publisheddate, 'YYYY-MM-DD') desc limit 31";    
    }

    query = client.query(queryString);
    
    var resultCollection = [];

    query.on('error', function(error) {
      //console.log('error: ' + error);
      res.json(resultCollection);
      done();
    });

    query.on('row', function(result) {
      if (!result) {
        // none
      } else {
        //console.log(result);
        resultCollection.push(result);
      }
    });

    //send the results
    query.on('end', function (err, result) {
      res.json(resultCollection);      
      done();
    });

  });

});


app.options('/api/gettopnewsevents', cors(corsOptions));
app.post('/api/gettopnewsevents', cors(corsOptions), function(req, res, next) {

  var accounts = '';

  if (req.body.accounts) {
    // Scrub array contents
    var accountArray = scrubArray(req.body.accounts);

    // Flatten the array
    accounts = accountArray.join("','");
  }

  // Filters
  //  var daysago;
  var resultCollection = [];
  var daysago = (req.body.daysago) ? scrubValue(req.body.daysago, 1) : 31;
  var limit = (req.body.limit) ? scrubValue(req.body.limit, 1) : 3;
  var source = scrubValue(req.body.source, 1);
  var importance = scrubValue(req.body.importance, 1);
  
  pg.connect(process.env.DATABASE_URL, function(err, client, done) {

    var handleError = function(err) {
      // no error occurred, continue with the request
      if(!err) return false;

      // An error occurred, remove the client from the connection pool.
      // A truthy value passed to done will remove the connection from the pool
      // instead of simply returning it to be reused.
      // In this case, if we have successfully received a client (truthy)
      // then it will be removed from the pool.
      done(client);
      res.writeHead(500, {'content-type': 'text/plain'});
      res.end('An error occurred');
      return true;
    };

    queryString = '';

    if (importance == '1' && source == '1')
    {
      // Twitter
      queryString = "SELECT *, extract(day from publisheddate) as daysago FROM collector WHERE publisheddate >= current_date - interval '" + daysago + " days' AND source = 1 AND accountid IN ('" + accounts + "') ORDER BY twitter_retweet DESC LIMIT " + limit + ";"
    }
    else if (importance == '1' && source == '0')
    {
      // News
      queryString = "SELECT *, extract(day from publisheddate) as daysago FROM collector WHERE publisheddate >= current_date - interval '" + daysago + " days' AND source = 0 AND accountid  IN ('" + accounts + "') ORDER BY news_vote DESC LIMIT " + limit + ";";
    }
    else {
      queryString = "SELECT *, extract(day from publisheddate) as daysago FROM Collector WHERE publisheddate >= current_date - interval '" + daysago + " days' AND accountid  IN ('" + accounts + "');";
    }

//    console.log(queryString);

    query = client.query(queryString);

    query.on('error', function(error) {
      //console.log('error: ' + error);
      res.json(resultCollection);
      done();
    });

    query.on('row', function(result) {
      if (!result) {
        //done();
      } else {
//        console.log(result);
        resultCollection.push(result);
      }
    });

    query.on('end', function (err, result) {
      done();

      res.json(resultCollection);
    });

  });
});




app.options('/api/getnewsevents', cors(corsOptions));
app.post('/api/getnewsevents', cors(corsOptions), function(req, res, next) {
  
  var accounts = req.body.accounts;

  if (req.body.accounts) {
    // Scrub array contents
    var accounts = scrubArray(req.body.accounts);

    // Flatten the array
    var accounts = req.body.accounts.join("','");
  }
  else {
    accounts = '';
  }

  // Filters
  var resultCollection = [];
  var daysago = (req.body.daysago) ? scrubValue(req.body.daysago, 1) : 31;

  if (accounts.length > 1)
  {

    pg.connect(process.env.DATABASE_URL, function(err, client, done) {
      queryString = 'WITH t1 AS (SELECT accountid, accountname, SUM(twitter_retweet) AS "twitter_retweet", max(twitter_retweet) AS "max_retweet", AVG(setiment) AS "avg_setiment", AVG(twitter_retweet) AS n   FROM collector WHERE publisheddate >= current_date - interval \'' + daysago + ' days\' AND source = 1 AND accountid IN (\'' + accounts + '\')   GROUP BY accountid, accountname) SELECT accountid, accountname, max_retweet, avg_setiment, n as "avg_retweet", 100.0 * twitter_retweet / sum(twitter_retweet + 0.1) over () as "percent_twitter_share" FROM t1;';

      query = client.query(queryString);
      
      query.on('error', function(error) {
        //console.log('error: ' + error);
        res.json(resultCollection);
        done();
      });

      query.on('row', function(result) {
      
        if (!result) {
          //done();
        } else {
          //console.log(result);
          resultCollection.push(result);
        }
      });
      query.on('end', function (err, result) {
        res.json(resultCollection);
        done();
      });

    });  
  }
  else
  {
    res.json(resultCollection);
  }

});



var getNewsArticles = function(accountCollection, nextRequestApi) {

  newsUrl = 'http://www.faroo.com/api?q=' + accountCollection.accountname + '&start=1&length=10&l=en&src=news&key=' + newsKey + '&f=json';

  console.log(newsUrl);

  client = new Client();

  client.get(newsUrl, function(data, response) {
    //console.log('--> Getting News for Account : ' + accountCollection.accountname);
    var dataresp = data.results;

    async.forEach(dataresp, function (item, callback){ 
      item['accountname'] = accountCollection.accountname;
      item['accountid'] = accountCollection.accountid;
      item['twittername'] = accountCollection.twittername;
      callback();
    }, function(err) {
      async.forEachLimit(dataresp, 1, addCollection, function(err){
        if (err) throw err;
          //console.log('+++ DONE all collection adds processed for ' + accountCollection.accountname);
      });
    });

    // Pause for 5 seconds before going to next....
    setTimeout(function() { nextRequestApi(); }, newsWaitTime);
  });
}


app.options('/api/intakenews', cors(corsOptions));
app.get('/api/intakenews', cors(corsOptions), function (req, res) {

    var accountCollection = new Array();
    var accountCollectionTwitter = new Array();

    async.waterfall(
      [
        
        // Get upcoming Events
        function(callback) {
            qGetEvents = 'SELECT e.Account.Name, e.Account.S1M_Twitter_Account__c, e.AccountId From Event e WHERE e.StartDateTime = NEXT_N_DAYS:' + EventWindow;
            
            org.query(qGetEvents, oauth, function(err, respMeetings) {

                //console.log('--- Upcoming Events ---');
                //console.log(respMeetings);
                //console.log('/// Upcoming Events ---');

                for(var item in respMeetings.records) {

                    // Make sure that an Account is somehow involved
                    if (respMeetings.records[item].Account)
                    {
                      //console.log('FOUND EVENT for Account : ' + respMeetings.records[item].Account.Name);
                      currentAccount = respMeetings.records[item].Account.Name;
                      currentAccountId = respMeetings.records[item].AccountId;
                      currentTwitter = respMeetings.records[item].Account.S1M_Twitter_Account__c;

                      accountCollection.push({accountname: currentAccount, accountid : currentAccountId, twittername : currentTwitter});
                    }
                }

                setTimeout(function() { callback(); }, 5000);
            });
        },
        
        // Get recently touched Accounts
        function(callback) {
            qGetAccountViewed = 'SELECT Id, Name, S1M_Twitter_Account__c FROM Account WHERE LastViewedDate = LAST_N_DAYS:' + AccountWindow;

            org.query(qGetAccountViewed, oauth, function(err, respRecentView) {

                //console.log('--- Recently Viewed Accounts ---');
                //console.log(respRecentView);
                //console.log('/// Recently Viewed Accounts ---');

                for(var item in respRecentView.records) {
                    //console.log('FOUND EVENT for Account : ' + respRecentView.records[item].Name);
                    currentAccount = respRecentView.records[item].Name;
                    currentAccountId = respRecentView.records[item].Id;
                    currentTwitter = respRecentView.records[item].S1M_Twitter_Account__c;

                    accountCollection.push({accountname: currentAccount, accountid : currentAccountId, twittername : currentTwitter});
                }

              callback();
            });
        }
    ],
    
    // Wrapping up
    function(err, status) {
 
        var cleanArray = cleanup(accountCollection, 'accountname');

        accountCollection = cleanArray;
        accountCollectionTwitter = cleanArray;

            async.parallel([
                function(callback) {
                  async.forEachLimit(accountCollection, 1, getNewsArticles, function(err){
                    if (err) throw err;
                      //console.log('done - with news (Faroo.com) for requests');
                    callback();
                  });
                },
                function(callback) {
                  
                  async.forEachLimit(accountCollectionTwitter, 1, getTwitterContent, function(err){
                     if (err) throw err;
                     console.log('done - with Twitter requests');
                     callback();
                  }); 

                }
            ], function(err) { //This is the final callback
                console.log('process complete');
            });
    }
  );

  res.json({ msg: 'ok' })
  res.end();  
});


app.options('/api/getevents', cors(corsOptions));
app.get('/api/getevents', cors(corsOptions), function(req, res, next) {

  var accounts = '';

  if (req.query.accounts) {
//    if (typeof req.query.accounts === 'object')
//    {
      // Flatten the array
      //accounts = accountArray.join("','");

      accountstring = req.query.accounts;

      accounts = accountstring.split(',');

      // Scrub array contents
      accounts = scrubArray(accounts);

      // Flatten the array
      accounts = accounts.join("','");
      
//    }
//    else
//    {
//      accounts = scrubValue(req.query.accounts);
//    }
  }
  
  // Filters
  var source = (req.query.source) ? scrubValue(req.query.source, 1) : -1;
  var daysago = (req.query.daysago) ? scrubValue(req.query.daysago, 1) : 7;
  var importance = (req.query.importance) ? scrubValue(req.query.importance, 1) : -1;
  var mapdata = (req.query.mapdata) ? scrubValue(req.query.mapdata, 1) : -1;
  var limit = (req.query.limit) ? scrubValue(req.query.limit, 1) : 3;

  pg.connect(process.env.DATABASE_URL, function(err, client, done) {

    if (mapdata == '1')
    {
      queryString = 'SELECT accountid, AVG(twitter_retweet) AS "avg_twitter_retweet", AVG(setiment) AS "avg_setiment" FROM collector WHERE publisheddate >= current_date - interval \'' + daysago + ' days\' AND accountid IN (\'' + accounts + '\') GROUP BY accountid ORDER BY "avg_twitter_retweet" DESC;';
    }
    else if (importance == '1' && source == '1')
    {
      // Twitter
      queryString = "SELECT *, extract(day from publisheddate) as daysago FROM collector WHERE publisheddate >= current_date - interval '" + daysago + " days' AND source = 1 AND accountid = '" + accounts + "' ORDER BY twitter_retweet DESC LIMIT " + limit + ";";
    }
    else if (importance == '1' && source == '0')
    {
      // News
      queryString = "SELECT *, extract(day from publisheddate) as daysago FROM collector WHERE publisheddate >= current_date - interval '" + daysago + " days' AND source = 0 AND accountid = '" + accounts + "' ORDER BY news_vote DESC LIMIT " + limit + ";";
    }
    else {
      queryString = "SELECT *, extract(day from publisheddate) as daysago FROM Collector WHERE publisheddate >= current_date - interval '" + daysago + " days' AND accountid IN ('" + accounts + "');";
    }

    //console.log(queryString);

    query = client.query(queryString);

    
    var resultCollection = [];
    query.on('row', function(result) {
    
      if (!result) {
        //done();
      } else {
        //console.log(result);
        resultCollection.push(result);
      }
    });

    //send the results
    query.on('end', function (err, result) {
      res.json(resultCollection);
      done();
    });
  });
});


// Run on first load - create database table if needed
pg.connect(process.env.DATABASE_URL, function(err, client, done) {

    client.query('CREATE TABLE IF NOT EXISTS collector (id SERIAL, iconlink character varying(255), title character varying(255), excerpt character varying(500), author character varying(100), link character varying(255), accountid character varying(18), accountname character varying(150), publisheddate date, source integer, setiment real, twitter_retweet integer, twitter_favorite integer, news_vote integer, CONSTRAINT "Collector_pkey" PRIMARY KEY (id) ) WITH ( OIDS=FALSE );',  function(err, result) {
      
      if(err) {
        console.log('ERROR : table not created, could not connect to database (make sure to configure your Heroku environment variables) or table may exist : ' + err);
        done();
      }
      else {
        console.log('SUCCESS : table created for S1 Ignition');
        done();
      }

  });
});


if(!module.parent){
  app.listen(port, function(){
    console.log('Express server listening on port ' + port + '.');
  });
}