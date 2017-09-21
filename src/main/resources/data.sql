-- boot feature to set data
/*
create table if not exists persistent_logins (
  username varchar(100) not null,
  series varchar(64) primary key,
  token varchar(64) not null,
  last_used timestamp not null
);
*/

-- Sec Question Definitions to use
/*
insert into security_question_definition (id, text) values (1, 'What is the last name of the teacher who gave you your first failing grade?');
insert into security_question_definition (id, text) values (2, 'What is the first name of the person you first kissed?');
insert into security_question_definition (id, text) values (3, 'What is the name of the place your wedding reception was held?');
insert into security_question_definition (id, text) values (4, 'When you were young, what did you want to be when you grew up?');
insert into security_question_definition (id, text) values (5, 'Where were you New Year''s 2000?');
insert into security_question_definition (id, text) values (6, 'Who was your childhood hero?');
*/

-- Test User done in post construct bean
--insert into user (id, email, password, enabled, created) values (1, 'test@mail.com', 'password', true, '2017-09-13 00:00:00');
--insert into security_question(id, user_id, security_question_definition_id, answer) values (1, 1, 6, 'Hulk');

