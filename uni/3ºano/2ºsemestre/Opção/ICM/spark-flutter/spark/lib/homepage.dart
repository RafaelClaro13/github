import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_database/firebase_database.dart';
import 'package:flutter/material.dart';
//import 'package:spark/Logics/functions.dart';
import 'package:spark/chatpage.dart';
import 'package:intl/intl.dart';
import 'comps/styles.dart';
import 'comps/widgets.dart';



class MyHomePage extends StatefulWidget {
  const MyHomePage({Key? key}) : super(key: key);
  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  @override
  void initState() {
    //Functions.updateAvailability();
    super.initState();
  }

  final firestore = FirebaseFirestore.instance;
  bool open = false;
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.blue,
      appBar: AppBar(
        backgroundColor: Colors.blue,
        title: const Text('Spark Chat'),
        elevation: 0,
        centerTitle: true,
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 10.0),
            child: IconButton(
                onPressed: () {
                  setState(() {
                    open == true ? open = false : open = true;
                  });
                },
                icon: Icon(
                  open == true ? Icons.close_rounded : Icons.search_rounded,
                  size: 30,
                )),
          )
        ],
      ),
      //drawer: ChatWidgets.drawer(context),
      body: SafeArea(
        child: Stack(
          alignment: AlignmentDirectional.topEnd,
          children: [
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  margin: const EdgeInsets.all(0),
                  child: Container(
                    color: Colors.blue,
                    padding: const EdgeInsets.all(8),
                    height: 160,
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Spacer(),
                        Padding(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 8.0, vertical: 10),
                          child: Text(
                            'Recent Users',
                            style: Styles.h1(),
                          ),
                        ),
                        Container(
                          margin: const EdgeInsets.symmetric(vertical: 10),
                          height: 80,
                          child: StreamBuilder(
                            stream:  firestore.collection('Rooms').snapshots(),
                            builder: (context, AsyncSnapshot<QuerySnapshot> snapshot) {
                              List data = !snapshot.hasData ? [] : snapshot.data!.docs.where((element) => element['users'].toString().contains(FirebaseAuth.instance.currentUser!.uid)).toList();
                              return ListView.builder(
                                scrollDirection: Axis.horizontal,
                                itemCount: data.length,
                                itemBuilder: (context, i) {
                                  List users = data[i]['users'];
                                  var friend = users.where((element) => element != FirebaseAuth.instance.currentUser!.uid);
                                  var user = friend.isNotEmpty ? friend.first : users .where((element) => element == FirebaseAuth.instance .currentUser!.uid).first;
                                  return  FutureBuilder(
                                    future: firestore.collection('Users').doc(user).get(),
                                    builder: (context, AsyncSnapshot snap) {
                                      return !snap.hasData? Container(): ChatWidgets.circleProfile(onTap: (){
                                        Navigator.of(context)
                                            .push(
                                          MaterialPageRoute(
                                            builder: (context) {
                                              return ChatPage(
                                                id: user,
                                                name: snap.data['name'],
                                              );
                                            },
                                          ),
                                        );
                                      },name:  snap.data['name']);
                                    }
                                  );
                                },
                              );
                            }
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
                Expanded(
                  child: Container(
                    margin: const EdgeInsets.only(top: 10),
                    decoration: Styles.friendsBox(),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Padding(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 20, vertical: 20),
                          child: Text(
                            'Contacts',
                            style: Styles.h1().copyWith(color: Colors.blue),
                          ),
                        ),
                        Expanded(
                          child: Padding(
                            padding:
                                const EdgeInsets.symmetric(horizontal: 12.0),
                            child: StreamBuilder(
                                stream:
                                    firestore.collection('Rooms').snapshots(),
                                builder: (context,
                                    AsyncSnapshot<QuerySnapshot> snapshot) {
                                  List data = !snapshot.hasData ? [] : snapshot.data!.docs.where((element) => element['users'].toString().contains(FirebaseAuth.instance.currentUser!.uid)).toList();
                                  return ListView.builder(
                                    itemCount: data.length,
                                    itemBuilder: (context, i) {
                                      List users = data[i]['users'];
                                      var friend = users.where((element) => element != FirebaseAuth.instance.currentUser!.uid);
                                      var user = friend.isNotEmpty ? friend.first : users .where((element) => element == FirebaseAuth.instance .currentUser!.uid).first;
                                      return FutureBuilder(
                                        future: firestore.collection('Users').doc(user).get(),
                                        builder: (context,AsyncSnapshot snap) {
                                          return !snap.hasData? Container(): ChatWidgets.card(
                                            title: snap.data['name'],
                                            subtitle:data[i]['last_message'],
                                            time: DateFormat('hh:mm a').format(data[i]['last_message_time'].toDate()),
                                            onTap: () {
                                              Navigator.of(context)
                                                  .push(
                                                MaterialPageRoute(
                                                  builder: (context) {
                                                    return ChatPage(
                                                      id: user,
                                                      name: snap.data['name'],
                                                    );
                                                  },
                                                ),
                                              );
                                            },
                                          );
                                        }
                                      );
                                    },
                                  );
                                }),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ),
            ChatWidgets.searchBar(open)
          ],
        ),
      ),
    );
  }
}
